<!-- Updated: 2026-04-07 by Constructor Tech -->

# Authorization Usage Scenarios

This document demonstrates the authorization model through concrete examples.
Each scenario shows the full flow: HTTP request → PDP evaluation → SQL execution.

For the core authorization design, see [DESIGN.md](./DESIGN.md).

All examples use a Task Management domain:
- **Resource:** `tasks` table with `id`, `owner_tenant_id`, `owner_id`, `title`, `status`
- **Owner:** `owner_id` references the subject (user) who owns/is assigned the task
- **Resource Groups:** Projects (tasks belong to projects)
- **Tenant Model:** Hierarchical multi-tenancy on a single-root tree — see [TENANT_MODEL.md](./TENANT_MODEL.md) for details on topology, barriers, and closure tables

---

## Table of Contents

- [Authorization Usage Scenarios](#authorization-usage-scenarios)
  - [Table of Contents](#table-of-contents)
  - [Projection Tables](#projection-tables)
    - [What Are Projection Tables?](#what-are-projection-tables)
    - [Choosing Projection Tables](#choosing-projection-tables)
    - [Capabilities and PDP Response](#capabilities-and-pdp-response)
    - [When No Projection Tables Are Needed](#when-no-projection-tables-are-needed)
    - [When to Use `tenant_closure`](#when-to-use-tenant_closure)
    - [`resource_group_membership` — When to Project](#resource_group_membership--when-to-project)
    - [When to Use `resource_group_closure`](#when-to-use-resource_group_closure)
    - [Combinations Summary](#combinations-summary)
  - [Scenarios](#scenarios)
    - [With `tenant_closure`](#with-tenant_closure)
      - [S01: LIST, tenant subtree, PEP has tenant\_closure](#s01-list-tenant-subtree-pep-has-tenant_closure)
      - [S02: GET, tenant subtree, PEP has tenant\_closure](#s02-get-tenant-subtree-pep-has-tenant_closure)
      - [S03: UPDATE, tenant subtree, PEP has tenant\_closure](#s03-update-tenant-subtree-pep-has-tenant_closure)
      - [S04: DELETE, tenant subtree, PEP has tenant\_closure](#s04-delete-tenant-subtree-pep-has-tenant_closure)
      - [S05: CREATE, PEP-provided tenant context](#s05-create-pep-provided-tenant-context)
      - [S06: CREATE, subject tenant context (no explicit tenant in API)](#s06-create-subject-tenant-context-no-explicit-tenant-in-api)
      - [S07: LIST, billing data, ignore barriers (barrier\_mode: "ignore")](#s07-list-billing-data-ignore-barriers-barrier_mode-ignore)
    - [Without `tenant_closure`](#without-tenant_closure)
      - [S08: LIST, tenant subtree, PEP without tenant\_closure](#s08-list-tenant-subtree-pep-without-tenant_closure)
      - [S09: GET, tenant subtree, PEP without tenant\_closure](#s09-get-tenant-subtree-pep-without-tenant_closure)
      - [S10: UPDATE, tenant subtree, PEP without tenant\_closure (prefetch)](#s10-update-tenant-subtree-pep-without-tenant_closure-prefetch)
      - [S11: DELETE, tenant subtree, PEP without tenant\_closure (prefetch)](#s11-delete-tenant-subtree-pep-without-tenant_closure-prefetch)
      - [S12: CREATE, PEP without tenant\_closure](#s12-create-pep-without-tenant_closure)
      - [S13: GET, context tenant only (no subtree)](#s13-get-context-tenant-only-no-subtree)
    - [Resource Groups](#resource-groups)
      - [S14: LIST, group membership, PEP has resource\_group\_membership (reference)](#s14-list-group-membership-pep-has-resource_group_membership-reference)
      - [S15: LIST, group subtree, PEP has closure + membership (reference)](#s15-list-group-subtree-pep-has-closure--membership-reference)
      - [S16: UPDATE, group membership, PEP has resource\_group\_membership (reference)](#s16-update-group-membership-pep-has-resource_group_membership-reference)
      - [S17: UPDATE, group subtree, PEP has closure + membership (reference)](#s17-update-group-subtree-pep-has-closure--membership-reference)
      - [S18: GET, group membership, domain service (no membership table)](#s18-get-group-membership-domain-service-no-membership-table)
      - [S19: LIST, group-based filtering, domain service (no group tables)](#s19-list-group-based-filtering-domain-service-no-group-tables)
    - [Advanced Patterns](#advanced-patterns)
      - [S20: LIST, tenant subtree and group membership (AND), domain service](#s20-list-tenant-subtree-and-group-membership-and-domain-service)
      - [S21: LIST, tenant subtree and group subtree, domain service](#s21-list-tenant-subtree-and-group-subtree-domain-service)
      - [S22: LIST, multiple access paths (OR)](#s22-list-multiple-access-paths-or)
      - [S23: Access denied](#s23-access-denied)
    - [Subject Owner-Based Access](#subject-owner-based-access)
      - [S24: LIST, owner-only access](#s24-list-owner-only-access)
      - [S25: GET, owner-only access](#s25-get-owner-only-access)
      - [S26: UPDATE, owner-only mutation](#s26-update-owner-only-mutation)
      - [S27: DELETE, owner-only mutation](#s27-delete-owner-only-mutation)
      - [S28: CREATE, owner-only](#s28-create-owner-only)
  - [TOCTOU Analysis](#toctou-analysis)
    - [When TOCTOU Matters](#when-toctou-matters)
    - [How Each Scenario Handles TOCTOU](#how-each-scenario-handles-toctou)
    - [Key Insight: Prefetch + Constraint for Mutations](#key-insight-prefetch--constraint-for-mutations)
  - [tr-authz-plugin Decision Matrix](#tr-authz-plugin-decision-matrix)
    - [Inputs](#inputs)
    - [Decision Table](#decision-table)
    - [R1 — Single-resource, explicit target tenant, root\_only](#r1--single-resource-explicit-target-tenant-root_only)
    - [R2 — Single-resource, explicit target tenant, subtree (default)](#r2--single-resource-explicit-target-tenant-subtree-default)
    - [R3 — Single-resource, no target tenant, root\_only](#r3--single-resource-no-target-tenant-root_only)
    - [R4 — Single-resource, no target tenant, subtree (default)](#r4--single-resource-no-target-tenant-subtree-default)
    - [R5 — List, explicit target tenant, root\_only](#r5--list-explicit-target-tenant-root_only)
    - [R6 — List, explicit target tenant, subtree (default)](#r6--list-explicit-target-tenant-subtree-default)
    - [R7 — List, no target tenant, root\_only](#r7--list-no-target-tenant-root_only)
    - [R8 — List, no target tenant, subtree (default)](#r8--list-no-target-tenant-subtree-default)
    - [Required Helpers](#required-helpers)
  - [References](#references)

---

## Projection Tables

### What Are Projection Tables?

**Projection tables** are local copies of hierarchical or relational data that enable efficient SQL-level authorization. Instead of calling external services during query execution, PEP uses these pre-synced tables to enforce constraints directly in the database.

**The problem they solve:** When PDP returns constraints like "user can access resources in tenant subtree T1", the PEP needs to translate this into SQL. Without local data, PEP would need to:
1. Call an external service to resolve the tenant hierarchy, or
2. Receive thousands of explicit tenant IDs from PDP (doesn't scale)

Projection tables allow PEP to JOIN against local data, making authorization O(1) regardless of hierarchy size.

**Types of projection tables:**

| Table | Purpose | Enables |
|-------|---------|---------|
| `tenant_closure` | Denormalized tenant hierarchy (ancestor→descendant pairs) | `in_tenant_subtree` predicate — efficient subtree queries without recursive CTEs |
| `resource_group` + `resource_group_closure` | Group entities + denormalized group hierarchy | Group hierarchy queries for PDP/PIP resolution |
| `resource_group_membership` + `gts_type` | Resource-to-group M:N associations, qualified by the RG-local type registry (the SQL resolves the resource's GTS type to `gts_type.id`) | `in_group`/`in_group_subtree` predicates at SQL level |

**Closure tables** specifically solve the hierarchy traversal problem. A closure table contains all ancestor-descendant pairs, allowing subtree queries with a simple `WHERE ancestor_id = X` instead of recursive tree walking.

> **Progressive projection (planned, not implemented):** no projection mechanism exists. SecureORM queries these tables by fixed name in whatever database the PEP's connection points at, so native predicates compile only where the tables are already present (the owning gear's own database, or a shared-database deployment). The rest of this note is design guidance for a future projection: do not add projections speculatively — each one creates an additional database and sync load. In a **monolith** with a single shared DB, no projections are needed (PEP JOINs against canonical tables). In **microservices**, start with `resource_group` + `resource_group_closure` (small tables, covers hierarchy). Only add `resource_group_membership` (with `gts_type`) when profiling confirms the two-request pattern is unacceptable for the latency budget — this table grows as `M_resources × N_groups_per_resource` and is expected to be **10×+ larger** than hierarchy tables (see [RG DESIGN §4.1 Database Size Analysis & Production Projections](../../../gears/system/resource-group/docs/DESIGN.md#41-database-size-analysis--production-projections)).

### Choosing Projection Tables

The choice depends on the application's tenant structure, resource organization, and **endpoint requirements**. Even with a hierarchical tenant model, specific endpoints may operate within a single context tenant (see S13).

### Capabilities and PDP Response

| PEP Capability | Projection Table | Prefetch | PDP Response | Available To |
|----------------|-----------------|----------|--------------|--------------|
| `tenant_hierarchy` | tenant_closure ✅ | **No** | `in_tenant_subtree` predicate | Account Management only (`tenant_closure` lives only in its database; projection to other domain services is planned, not implemented) |
| (none) | ❌ | **Yes** | `eq`/`in` or decision only | Domain services |
| `group_hierarchy` + `group_membership` | resource_group_closure + resource_group_membership + gts_type ✅ | **No** | `in_group_subtree` predicate | PEPs with RG tables in their DB whose resource type opts in via `with_native_group_predicates()` (no gear opts in) |
| `group_membership` | resource_group_membership + gts_type ✅ | **No** | `in_group` predicate | PEPs with RG tables in their DB whose resource type opts in via `with_native_group_predicates()` (no gear opts in) |
| (none for groups) | ❌ | **Yes** | explicit resource IDs via `in` | Domain services |

**Note:** `group_membership` and `group_hierarchy` capabilities require the `resource_group_membership` table (plus `gts_type`, which the generated SQL uses to resolve the resource's GTS type). This table is expected to be 10×+ larger than other projections. By default, domain services operate in the "(none for groups)" row — PDP resolves group memberships into explicit resource IDs. See [below](#resource_group_membership--when-to-project) for guidance on when a projection would be warranted once one exists (planned, not implemented).

### When No Projection Tables Are Needed

| Condition | Why Tables Aren't Required |
|-----------|---------------------------|
| Endpoint operates in context tenant only | No subtree traversal → `eq` on `owner_tenant_id` is sufficient (see S13) |
| Few tenants per vendor | PDP can return explicit tenant IDs in `in` predicate |
| Flat tenant structure | No hierarchy → `in_tenant_subtree` not needed |
| No resource groups | `in_group*` predicates not used |
| Low frequency LIST requests | Prefetch overhead is acceptable |

**Important:** The first condition applies regardless of overall tenant model. Even in a hierarchical multi-tenant system, specific endpoints may be designed to work within a single context tenant without subtree access. This is an endpoint-level decision, not a system-wide constraint.

**Example:** Internal enterprise tool with 10 tenants, flat structure. Or: a "My Tasks" endpoint that shows only tasks in user's direct tenant, even though the system supports tenant hierarchy for other operations.

### When to Use `tenant_closure`

| Condition | Why Closure Is Needed |
|-----------|----------------------|
| Tenant hierarchy (parent-child) + many tenants | PDP cannot return all IDs in `in` predicate |
| Frequent LIST requests by subtree | Subtree JOINs more efficient than explicit ID lists |

**Note:** Self-managed tenants (barriers) and tenant status filtering can be checked by PDP on its side — this doesn't require closure on PEP side.

**Example:** Multi-tenant SaaS with organization hierarchy (org → teams → projects) and thousands of tenants.

### `resource_group_membership` — When to Project

The `resource_group_membership` table grows as `M_resources × N_groups_per_resource` and is expected to be **10× or more larger** than other projection tables. Concrete estimates depend on vendor scale — see [RG DESIGN §4.1 Database Size Analysis & Production Projections](../../../gears/system/resource-group/docs/DESIGN.md#41-database-size-analysis--production-projections). Do not project it speculatively. No projection mechanism exists; the guidance below is for a planned, not-yet-implemented projection.

**Decision guide:**

| Deployment | Pattern | Project membership? |
|------------|---------|-------------------|
| **Monolith** (shared DB) | PEP JOINs canonical tables directly | **No** — already co-located |
| **Microservices** (simple access checks) | PDP resolves memberships → `in` predicates | **No** — default, works for point operations and simple lists |
| **Microservices** (filtered/paginated by group attributes) | Two-request: RG Membership API → domain service | **No** — but note this may mean N round-trips (see below) |
| **Microservices** (N-request fan-out is unacceptable) | Local membership table | **Yes (planned, not implemented)** — only after profiling confirms latency impact |

**Two-request pattern and its limits:** instead of projecting, split the query:
1. Call the **RG Membership API** to obtain the matching resource IDs.
2. Fetch the objects from the **domain service** by those IDs.

This works well for simple paginated listing. However, when the query includes filters by resource group attributes (e.g., `GET /tasks?status=pending&project={projectX}&after=…&limit=50`), the pattern requires **N additional round-trips** to the RG Membership API — one per filter-group or page — not just a single +1. If this N-request fan-out violates the latency budget, that is the signal for the planned (not yet implemented) local membership projection; until it exists, the options are the two-request pattern or PDP degradation.

**For domain services (default):** PDP resolves group memberships and returns explicit resource IDs via `in` predicates (capability degradation). No local membership table is needed.

**Native group predicates (supported, not used):** the SDK and SecureORM can compile `in_group` and `in_group_subtree` into SQL subqueries over `resource_group_membership` (+ `resource_group_closure` and `gts_type`) for a service that has those tables in its database (the RG gear's own database, or a shared-database deployment) and whose resource type opts in via `ResourceType::with_native_group_predicates()`. No gear opts in — the RG gear's own group resource deliberately does not, since group nesting is hierarchy, not membership (see [RESOURCE_GROUP_MODEL.md](./RESOURCE_GROUP_MODEL.md)).

### When to Use `resource_group_closure`

| Condition | Why Group Closure Is Needed |
|-----------|----------------------------|
| Group hierarchy | Nested folders, sub-projects |
| Subtree queries by groups | "Show all in folder and subfolders" |
| Many groups | PDP cannot expand entire hierarchy to explicit IDs |

**Example:** Document management with nested folders.

### Combinations Summary

| Use Case | tenant_closure | group_membership | group_closure |
|----------|----------------|------------------|---------------|
| Simple SaaS (flat tenants, no groups) | ❌ | ❌ | ❌ |
| Enterprise SaaS (tenant hierarchy) | ✅ | ❌ | ❌ |
| Project-based SaaS (flat tenants + projects) | ❌ | ✅ | ❌ |
| Complex SaaS (hierarchy + nested projects) | ✅ | ✅ | ✅ |

> **Note:** Rows that use `group_membership` or `group_closure` describe reference deployments (e.g., a monolith) where the `resource_group_membership` table is co-located with the domain service and the resource type opts in to native group predicates (no gear does). Domain services in separate deployments do **not** have `resource_group_membership` (no projection mechanism exists, and the table is too large to project speculatively). For those cases, PDP resolves group memberships and returns explicit resource IDs via `in` predicates (capability degradation) — the domain service remains in the top row regardless of group usage.

---

## Scenarios

> **Note:** SQL examples use subqueries for clarity. Production implementations
> may use JOINs or EXISTS for performance optimization.

### With `tenant_closure`

PEP has local tenant_closure table → can enforce `in_tenant_subtree` predicates.

---

#### S01: LIST, tenant subtree, PEP has tenant_closure

`GET /tasks?tenant_subtree=true`

User requests all tasks visible in their tenant subtree.

**Request:**
```http
GET /tasks?tenant_subtree=true
Authorization: Bearer <token>
```

**PEP → PDP Request:**
```json
{
  "subject": {
    "type": "gts.cf.core.security.subject_user.v1~",
    "id": "user123-uuid",
    "properties": { "tenant_id": "T1-uuid" }
  },
  "action": { "name": "list" },
  "resource": { "type": "gts.cf.core.tasks.task.v1~" },
  "context": {
    "tenant_context": {
      "mode": "subtree",
      "root_id": "T1-uuid",
      "barrier_mode": "respect"
    },
    "require_constraints": true,
    "capabilities": ["tenant_hierarchy"],
    "supported_properties": ["owner_tenant_id", "id"]
  }
}
```

**PDP → PEP Response:**
```json
{
  "decision": true,
  "context": {
    "constraints": [
      {
        "predicates": [
          {
            "op": "in_tenant_subtree",
            "property": "owner_tenant_id",
            "root_tenant_id": "T1-uuid",
            "barrier_mode": "respect"
          }
        ]
      }
    ]
  }
}
```

**SQL:**
```sql
SELECT * FROM tasks
WHERE owner_tenant_id IN (
  SELECT descendant_id FROM tenant_closure
  WHERE ancestor_id = 'T1-uuid'
    AND barrier = 0
)
```

---

#### S02: GET, tenant subtree, PEP has tenant_closure

`GET /tasks/{id}?tenant_subtree=true`

User requests a specific task; PEP enforces tenant subtree access at query level.

**Request:**
```http
GET /tasks/task456-uuid?tenant_subtree=true
Authorization: Bearer <token>
```

**PEP → PDP Request:**
```json
{
  "subject": {
    "type": "gts.cf.core.security.subject_user.v1~",
    "id": "user123-uuid",
    "properties": { "tenant_id": "T1-uuid" }
  },
  "action": { "name": "read" },
  "resource": {
    "type": "gts.cf.core.tasks.task.v1~",
    "id": "task456-uuid"
  },
  "context": {
    "tenant_context": {
      "mode": "subtree",
      "root_id": "T1-uuid"
    },
    "require_constraints": true,
    "capabilities": ["tenant_hierarchy"],
    "supported_properties": ["owner_tenant_id", "id"]
  }
}
```

**PDP → PEP Response:**
```json
{
  "decision": true,
  "context": {
    "constraints": [
      {
        "predicates": [
          {
            "op": "in_tenant_subtree",
            "property": "owner_tenant_id",
            "root_tenant_id": "T1-uuid"
          }
        ]
      }
    ]
  }
}
```

**SQL:**
```sql
SELECT * FROM tasks
WHERE id = 'task456-uuid'
  AND owner_tenant_id IN (
    SELECT descendant_id FROM tenant_closure
    WHERE ancestor_id = 'T1-uuid'
      AND barrier = 0  -- barrier_mode defaults to "respect"
  )
```

**Result interpretation:**
- 1 row → return task
- 0 rows → **404 Not Found** (hides resource existence from unauthorized users)

---

#### S03: UPDATE, tenant subtree, PEP has tenant_closure

`PUT /tasks/{id}?tenant_subtree=true`

User updates a task; constraint ensures atomic authorization check.

**Request:**
```http
PUT /tasks/task456-uuid?tenant_subtree=true
Authorization: Bearer <token>
Content-Type: application/json

{"status": "completed"}
```

**PEP → PDP Request:**
```json
{
  "subject": {
    "type": "gts.cf.core.security.subject_user.v1~",
    "id": "user123-uuid",
    "properties": { "tenant_id": "T1-uuid" }
  },
  "action": { "name": "update" },
  "resource": {
    "type": "gts.cf.core.tasks.task.v1~",
    "id": "task456-uuid"
  },
  "context": {
    "tenant_context": {
      "mode": "subtree",
      "root_id": "T1-uuid"
    },
    "require_constraints": true,
    "capabilities": ["tenant_hierarchy"],
    "supported_properties": ["owner_tenant_id", "id"]
  }
}
```

**PDP → PEP Response:**
```json
{
  "decision": true,
  "context": {
    "constraints": [
      {
        "predicates": [
          {
            "op": "in_tenant_subtree",
            "property": "owner_tenant_id",
            "root_tenant_id": "T1-uuid"
          }
        ]
      }
    ]
  }
}
```

**SQL:**
```sql
UPDATE tasks
SET status = 'completed'
WHERE id = 'task456-uuid'
  AND owner_tenant_id IN (
    SELECT descendant_id FROM tenant_closure
    WHERE ancestor_id = 'T1-uuid'
      AND barrier = 0  -- barrier_mode defaults to "respect"
  )
```

**Result interpretation:**
- 1 row affected → success
- 0 rows affected → **404 Not Found** (task doesn't exist or no access)

---

#### S04: DELETE, tenant subtree, PEP has tenant_closure

`DELETE /tasks/{id}?tenant_subtree=true`

DELETE follows the same pattern as UPDATE (S03). PDP returns `in_tenant_subtree` constraint, PEP applies it in the DELETE's WHERE clause.

**SQL:**
```sql
DELETE FROM tasks
WHERE id = 'task456-uuid'
  AND owner_tenant_id IN (
    SELECT descendant_id FROM tenant_closure
    WHERE ancestor_id = 'T1-uuid'
      AND barrier = 0  -- barrier_mode defaults to "respect"
  )
```

**Result interpretation:**
- 1 row affected → success
- 0 rows affected → **404 Not Found** (task doesn't exist or no access)

---

#### S05: CREATE, PEP-provided tenant context

`POST /tasks`

User creates a new task. PDP returns constraints for CREATE just like other operations — the PEP will enforce them before the INSERT.

**Request:**
```http
POST /tasks
Authorization: Bearer <token>
Content-Type: application/json

{"title": "New Task", "owner_tenant_id": "T2-uuid"}
```

**PEP → PDP Request:**
```json
{
  "subject": {
    "type": "gts.cf.core.security.subject_user.v1~",
    "id": "user123-uuid",
    "properties": { "tenant_id": "T1-uuid" }
  },
  "action": { "name": "create" },
  "resource": {
    "type": "gts.cf.core.tasks.task.v1~",
    "properties": {
      "owner_tenant_id": "T2-uuid"
    }
  },
  "context": {
    "tenant_context": {
      "mode": "root_only",
      "root_id": "T2-uuid"
    },
    "require_constraints": true,
    "capabilities": ["tenant_hierarchy"],
    "supported_properties": ["owner_tenant_id", "id"]
  }
}
```

**PDP → PEP Response:**
```json
{
  "decision": true,
  "context": {
    "constraints": [
      {
        "predicates": [
          {
            "op": "eq",
            "property": "owner_tenant_id",
            "value": "T2-uuid"
          }
        ]
      }
    ]
  }
}
```

**PEP compiles constraints**, then enforces them before the INSERT:

**SQL:**
```sql
INSERT INTO tasks (id, owner_tenant_id, title, status)
VALUES ('tasknew-uuid', 'T2-uuid', 'New Task', 'pending')
```

**Note:** PDP returns constraints for CREATE using the same flow as other operations. PEP validates that the INSERT's `owner_tenant_id` (or other resource properties in case of RBAC) matches the constraint. This prevents the caller from creating resources in tenants the PDP didn't authorize.

---

#### S06: CREATE, subject tenant context (no explicit tenant in API)

`POST /tasks`

PEP's API does not include a target tenant in the request body. PEP uses `subject_tenant_id` from `SecurityContext` as the `owner_tenant_id` for the new resource, then sends it to PDP for validation — same flow as S05.

**Request:**
```http
POST /tasks
Authorization: Bearer <token>
Content-Type: application/json

{"title": "New Task"}
```

**PEP resolves tenant from SecurityContext:**

The PEP reads `subject_tenant_id` (T1-uuid) from the `SecurityContext` produced by AuthN Resolver. This is the subject's home tenant — the natural owner for the new resource when no explicit tenant is provided in the API.

**PEP → PDP Request:**
```json
{
  "subject": {
    "type": "gts.cf.core.security.subject_user.v1~",
    "id": "user123-uuid",
    "properties": { "tenant_id": "T1-uuid" }
  },
  "action": { "name": "create" },
  "resource": {
    "type": "gts.cf.core.tasks.task.v1~",
    "properties": {
      "owner_tenant_id": "T1-uuid"
    }
  },
  "context": {
    "tenant_context": {
      "mode": "root_only",
      "root_id": "T1-uuid"
    },
    "require_constraints": true,
    "capabilities": ["tenant_hierarchy"],
    "supported_properties": ["owner_tenant_id", "id"]
  }
}
```

**PDP → PEP Response:**
```json
{
  "decision": true,
  "context": {
    "constraints": [
      {
        "predicates": [
          {
            "op": "eq",
            "property": "owner_tenant_id",
            "value": "T1-uuid"
          }
        ]
      }
    ]
  }
}
```

**PEP compiles constraints**, then enforces them before the INSERT:

**SQL:**
```sql
INSERT INTO tasks (id, owner_tenant_id, title, status)
VALUES ('tasknew-uuid', 'T1-uuid', 'New Task', 'pending')
```

**Difference from S05:** In S05, PEP knows the target tenant from the request body (explicit `owner_tenant_id` field). Here, the API has no tenant field — PEP uses `SecurityContext.subject_tenant_id` instead. Both scenarios follow the same PDP validation flow.

**Design rationale:** Constraints are enforcement predicates (WHERE clauses), not a data source. The PEP should never extract `owner_tenant_id` for INSERT from PDP constraints. Instead, the tenant for a new resource is always determined by the PEP — either from the request body (S05) or from `SecurityContext.subject_tenant_id` (S06) — and then validated by the PDP through the standard constraint flow.

---

#### S07: LIST, billing data, ignore barriers (barrier_mode: "ignore")

`GET /billing/usage?tenant_subtree=true&barrier_mode=ignore`

Billing service needs usage data from all tenants in subtree, including self-managed tenants (barriers ignored). This is a cross-barrier operation for administrative purposes.

**Tenant hierarchy:**
```text
T1 (parent)
├── T2 (self_managed=true)  ← barrier (ignored for billing)
│   └── T3
└── T4
```

**Request:**
```http
GET /billing/usage?tenant_subtree=true&barrier_mode=ignore
Authorization: Bearer <token>
```

**PEP → PDP Request:**
```json
{
  "subject": {
    "type": "gts.cf.core.security.subject_user.v1~",
    "id": "user123-uuid",
    "properties": { "tenant_id": "T1-uuid" }
  },
  "action": { "name": "list" },
  "resource": { "type": "gts.cf.core.billing.usage.v1~" },
  "context": {
    "tenant_context": {
      "mode": "subtree",
      "root_id": "T1-uuid",
      "barrier_mode": "ignore"
    },
    "require_constraints": true,
    "capabilities": ["tenant_hierarchy"],
    "supported_properties": ["owner_tenant_id", "id"]
  }
}
```

**PDP → PEP Response:**
```json
{
  "decision": true,
  "context": {
    "constraints": [
      {
        "predicates": [
          {
            "op": "in_tenant_subtree",
            "property": "owner_tenant_id",
            "root_tenant_id": "T1-uuid",
            "barrier_mode": "ignore"
          }
        ]
      }
    ]
  }
}
```

**SQL:**
```sql
SELECT * FROM billing_usage
WHERE owner_tenant_id IN (
  SELECT descendant_id FROM tenant_closure
  WHERE ancestor_id = 'T1-uuid'
  -- no barrier clause because barrier_mode = "ignore"
)
```

**Result:** Returns usage data from T1, T2, T3, and T4. Barriers are ignored for billing operations.

**tenant_closure data example:**

| ancestor_id | descendant_id | barrier |
|-------------|---------------|---------|
| T1-uuid | T1-uuid | 0 |
| T1-uuid | T2-uuid | 1 |
| T1-uuid | T3-uuid | 1 |
| T1-uuid | T4-uuid | 0 |
| T2-uuid | T2-uuid | 0 |
| T2-uuid | T3-uuid | 0 |

When querying from T1 with `barrier_mode=respect`, only rows where `barrier = 0` match → T1, T4.

**Key insight:** T2 → T2 and T2 → T3 have `barrier = 0` because the `barrier` column is defined over the interval **`(ancestor, descendant]`** — the ancestor endpoint is excluded (canonical definition in [TENANT_MODEL.md §Closure Table](./TENANT_MODEL.md#closure-table)). When T2 is the query root, its self_managed status doesn't block access to its own subtree.

---

### Without `tenant_closure`

PEP has no tenant_closure table → PDP returns explicit IDs or PEP prefetches attributes.

---

#### S08: LIST, tenant subtree, PEP without tenant_closure

`GET /tasks?tenant_subtree=true`

PEP doesn't have tenant_closure. PDP resolves the subtree and returns explicit tenant IDs.

**Request:**
```http
GET /tasks?tenant_subtree=true
Authorization: Bearer <token>
```

**PEP → PDP Request:**
```json
{
  "subject": {
    "type": "gts.cf.core.security.subject_user.v1~",
    "id": "user123-uuid",
    "properties": { "tenant_id": "T1-uuid" }
  },
  "action": { "name": "list" },
  "resource": { "type": "gts.cf.core.tasks.task.v1~" },
  "context": {
    "tenant_context": {
      "mode": "subtree",
      "root_id": "T1-uuid"
    },
    "require_constraints": true,
    "capabilities": [],
    "supported_properties": ["owner_tenant_id", "id"]
  }
}
```

**PDP → PEP Response:**

PDP resolves the subtree internally and returns explicit IDs:

```json
{
  "decision": true,
  "context": {
    "constraints": [
      {
        "predicates": [
          {
            "op": "in",
            "property": "owner_tenant_id",
            "values": ["T1-uuid", "T2-uuid", "T3-uuid"]
          }
        ]
      }
    ]
  }
}
```

**SQL:**
```sql
SELECT * FROM tasks
WHERE owner_tenant_id IN ('T1-uuid', 'T2-uuid', 'T3-uuid')
```

**Trade-off:** PDP must know the tenant hierarchy and resolve it. Works well for small tenant counts; may not scale for thousands of tenants.

---

#### S09: GET, tenant subtree, PEP without tenant_closure

`GET /tasks/{id}?tenant_subtree=true`

PEP doesn't have tenant_closure. PEP fetches the resource first (prefetch), then asks PDP for an access decision based on resource attributes with `require_constraints: false`. Since PEP already has the entity, it doesn't need row-level SQL constraints — the PDP decision alone is sufficient.

If the PDP returns `decision: true` **without** constraints, PEP returns the prefetched entity directly (no second query). If the PDP returns constraints despite `require_constraints: false`, PEP compiles them and performs a scoped re-read as a fallback.

**Request:**
```http
GET /tasks/task456-uuid?tenant_subtree=true
Authorization: Bearer <token>
```

**Step 1 — PEP prefetches resource:**
```sql
SELECT * FROM tasks WHERE id = 'task456-uuid'
```
Result: full task record with `owner_tenant_id = 'T2-uuid'`

**Step 2 — PEP → PDP Request (with resource properties, `require_constraints: false`):**
```json
{
  "subject": {
    "type": "gts.cf.core.security.subject_user.v1~",
    "id": "user123-uuid",
    "properties": { "tenant_id": "T1-uuid" }
  },
  "action": { "name": "read" },
  "resource": {
    "type": "gts.cf.core.tasks.task.v1~",
    "id": "task456-uuid",
    "properties": {
      "owner_tenant_id": "T2-uuid"
    }
  },
  "context": {
    "tenant_context": {
      "mode": "subtree",
      "root_id": "T1-uuid"
    },
    "require_constraints": false,
    "capabilities": [],
    "supported_properties": ["owner_tenant_id", "id"]
  }
}
```

**PDP → PEP Response:**

PDP validates that T2 is in T1's subtree. Since `require_constraints: false`, PDP may return a decision-only response (no constraints):

```json
{
  "decision": true,
  "context": {
    "constraints": []
  }
}
```

Alternatively, PDP may still return constraints (e.g., `eq(owner_tenant_id, T2-uuid)`) — the PEP handles both cases.

**Step 3 — Enforce and return result:**

PEP compiles the response into `AccessScope`:
- **No constraints** (`scope.is_unconstrained()`) → return the prefetched entity directly. No second SQL query needed.
- **Constraints returned** → compile to `AccessScope` and perform a scoped re-read (`SELECT ... WHERE id = 'task456-uuid' AND owner_tenant_id = 'T2-uuid'`).
- Resource not found in Step 1 → **404 Not Found**.
- `decision: false` → **404 Not Found** (hides resource existence from unauthorized callers).

**Why no TOCTOU concern:** For GET, the "use" is returning data to the client. Even if `owner_tenant_id` changed between prefetch and response, no security violation occurs — the client either gets data they had access to at query time, or gets 404. For mutations (UPDATE/DELETE), see S10.

---

#### S10: UPDATE, tenant subtree, PEP without tenant_closure (prefetch)

`PUT /tasks/{id}?tenant_subtree=true`

Unlike S09 (GET), mutations require TOCTOU protection. PEP prefetches `owner_tenant_id`, gets `eq` constraint from PDP, and applies it in UPDATE's WHERE clause. This ensures atomic check-and-modify.

**Request:**
```http
PUT /tasks/task456-uuid?tenant_subtree=true
Authorization: Bearer <token>
Content-Type: application/json

{"status": "completed"}
```

**Step 1 — PEP prefetches:**
```sql
SELECT owner_tenant_id FROM tasks WHERE id = 'task456-uuid'
```
Result: `owner_tenant_id = 'T2-uuid'`

**Step 2 — PEP → PDP Request:**
```json
{
  "subject": {
    "type": "gts.cf.core.security.subject_user.v1~",
    "id": "user123-uuid",
    "properties": { "tenant_id": "T1-uuid" }
  },
  "action": { "name": "update" },
  "resource": {
    "type": "gts.cf.core.tasks.task.v1~",
    "id": "task456-uuid",
    "properties": {
      "owner_tenant_id": "T2-uuid"
    }
  },
  "context": {
    "tenant_context": {
      "mode": "subtree",
      "root_id": "T1-uuid"
    },
    "require_constraints": true,
    "capabilities": [],
    "supported_properties": ["owner_tenant_id", "id"]
  }
}
```

**PDP → PEP Response:**
```json
{
  "decision": true,
  "context": {
    "constraints": [
      {
        "predicates": [
          {
            "op": "eq",
            "property": "owner_tenant_id",
            "value": "T2-uuid"
          }
        ]
      }
    ]
  }
}
```

**Step 3 — SQL with constraint:**
```sql
UPDATE tasks
SET status = 'completed'
WHERE id = 'task456-uuid'
  AND owner_tenant_id = 'T2-uuid'
```

**TOCTOU protection:** If another request changed `owner_tenant_id` between prefetch and UPDATE, the WHERE clause won't match → 0 rows affected → **404**. This prevents unauthorized modification even in a race condition.

---

#### S11: DELETE, tenant subtree, PEP without tenant_closure (prefetch)

`DELETE /tasks/{id}?tenant_subtree=true`

DELETE follows the same pattern as UPDATE (S10). PEP prefetches `owner_tenant_id`, gets `eq` constraint from PDP, and applies it in the DELETE's WHERE clause.

**SQL:**
```sql
DELETE FROM tasks
WHERE id = 'task456-uuid'
  AND owner_tenant_id = 'T2-uuid'
```

TOCTOU protection is identical to S10: if `owner_tenant_id` changed between prefetch and DELETE, the WHERE clause won't match → 0 rows → **404**.

---

#### S12: CREATE, PEP without tenant_closure

CREATE does not query existing rows, so the presence of `tenant_closure` is irrelevant. Both PEP-provided and PDP-resolved tenant patterns work identically regardless of PEP capabilities. See S05 and S06.

**`require_constraints: false` optimization:** When PEP sends resource properties (e.g., `owner_tenant_id` of the entity being created) to the PDP, it can set `require_constraints: false`. If the PDP returns `decision: true` without constraints, the resulting `AccessScope` is `allow_all()`, and `validate_insert_scope` skips validation (its `is_unconstrained()` fast path). If the PDP returns constraints, they are compiled and validated against the insert as usual. This avoids unnecessary constraint compilation when the PDP decision alone is sufficient.

---

#### S13: GET, context tenant only (no subtree)

`GET /tasks/{id}`

Simplest case — access limited to context tenant only, no subtree traversal. User can only access resources directly owned by their tenant.

**Request:**
```http
GET /tasks/task456-uuid
Authorization: Bearer <token>
```

**PEP → PDP Request:**
```json
{
  "subject": {
    "type": "gts.cf.core.security.subject_user.v1~",
    "id": "user123-uuid",
    "properties": { "tenant_id": "T1-uuid" }
  },
  "action": { "name": "read" },
  "resource": {
    "type": "gts.cf.core.tasks.task.v1~",
    "id": "task456-uuid"
  },
  "context": {
    "tenant_context": {
      "mode": "root_only",
      "root_id": "T1-uuid"
    },
    "require_constraints": true,
    "capabilities": [],
    "supported_properties": ["owner_tenant_id", "id"]
  }
}
```

**PDP → PEP Response:**
```json
{
  "decision": true,
  "context": {
    "constraints": [
      {
        "predicates": [
          {
            "op": "eq",
            "property": "owner_tenant_id",
            "value": "T1-uuid"
          }
        ]
      }
    ]
  }
}
```

**SQL:**
```sql
SELECT * FROM tasks
WHERE id = 'task456-uuid'
  AND owner_tenant_id = 'T1-uuid'
```

**Note:** No prefetch needed, no closure table required. PDP returns direct `eq` constraint based on context tenant. This pattern applies when the endpoint operates within a single-tenant context, regardless of whether the overall tenant model is hierarchical.

---

### Resource Groups

> **Note:** Resource groups are tenant-scoped. A PDP **should** guarantee that any `group_ids` or `ancestor_ids` returned in constraints belong to the request context tenant. The shipped `tr-authz-plugin` does **not** validate this: it passes the caller-supplied `group_ids` / `ancestor_group_ids` resource properties through unchanged (after UUID parsing).
>
> All group-based constraints also include a tenant predicate on the resource (typically `eq`/`in` on `owner_tenant_id`) in the same constraint, so tenant isolation at the resource level holds even when a supplied group ID belongs to another tenant.
>
> **Important — projection architecture:** `resource_group_membership` grows as `M_resources × N_groups_per_resource` and is expected to be 10×+ larger than hierarchy tables. No projection mechanism exists; a planned projection would be warranted only when profiling confirms the two-request pattern is unacceptable (see [When to Project](#resource_group_membership--when-to-project)). `in_group`/`in_group_subtree` predicates require this table (plus `gts_type`) and are only executable when it is present in the PEP's database (the RG gear's own database, or a shared-database deployment) and the resource type opts in via `ResourceType::with_native_group_predicates()` — no gear does. By default, domain services rely on PDP capability degradation — PDP resolves group memberships internally and returns degraded predicates: explicit resource IDs via `in`, or `eq` for point operations. Scenarios S14–S17 below are reference patterns (require membership table); S18–S19 are the standard domain service patterns.

---

#### S14: LIST, group membership, PEP has resource_group_membership (reference)

`GET /tasks`

User has access to specific projects (flat group membership, no hierarchy).

> **Reference pattern:** This scenario requires `resource_group_membership` (and `gts_type`) in the PEP's database and a resource type that opts in via `ResourceType::with_native_group_predicates()`. The SDK and SecureORM support this, but no gear opts in; since no projection mechanism exists, it would apply only to a service whose database holds the RG tables (the RG gear's own database, or a shared-database deployment). For the standard domain service pattern, see S19.

**Request:**
```http
GET /tasks
Authorization: Bearer <token>
```

**PEP → PDP Request:**
```json
{
  "subject": {
    "type": "gts.cf.core.security.subject_user.v1~",
    "id": "user123-uuid",
    "properties": { "tenant_id": "T1-uuid" }
  },
  "action": { "name": "list" },
  "resource": { "type": "gts.cf.core.tasks.task.v1~" },
  "context": {
    "tenant_context": {
      "mode": "root_only",
      "root_id": "T1-uuid"
    },
    "require_constraints": true,
    "capabilities": ["group_membership"],
    "supported_properties": ["owner_tenant_id", "id"]
  }
}
```

**PDP → PEP Response:**

Tenant constraint is always included — groups don't bypass tenant isolation:

```json
{
  "decision": true,
  "context": {
    "constraints": [
      {
        "predicates": [
          {
            "op": "eq",
            "property": "owner_tenant_id",
            "value": "T1-uuid"
          },
          {
            "op": "in_group",
            "property": "id",
            "group_ids": ["ProjectA-uuid", "ProjectB-uuid"]
          }
        ]
      }
    ]
  }
}
```

**SQL:**
```sql
SELECT * FROM tasks
WHERE owner_tenant_id = 'T1-uuid'
  AND CAST(id AS text) IN (
    SELECT resource_id FROM resource_group_membership
    WHERE group_id IN ('ProjectA-uuid', 'ProjectB-uuid')
      AND gts_type_id IN (
        SELECT id FROM gts_type
        WHERE schema_id = 'gts.cf.core.tasks.task.v1~'
      )
  )
```

---

#### S15: LIST, group subtree, PEP has closure + membership (reference)

`GET /tasks`

User has access to a project folder and all its subfolders.

> **Reference pattern:** This scenario requires `resource_group_closure`, `resource_group_membership` and `gts_type` in the PEP's database and a resource type that opts in via `ResourceType::with_native_group_predicates()`. The SDK and SecureORM support this, but no gear opts in; since no projection mechanism exists, it would apply only to a service whose database holds the RG tables (the RG gear's own database, or a shared-database deployment). For the standard domain service pattern, see S19.

**Request:**
```http
GET /tasks
Authorization: Bearer <token>
```

**PEP → PDP Request:**
```json
{
  "subject": {
    "type": "gts.cf.core.security.subject_user.v1~",
    "id": "user123-uuid",
    "properties": { "tenant_id": "T1-uuid" }
  },
  "action": { "name": "list" },
  "resource": { "type": "gts.cf.core.tasks.task.v1~" },
  "context": {
    "tenant_context": {
      "mode": "root_only",
      "root_id": "T1-uuid"
    },
    "require_constraints": true,
    "capabilities": ["group_membership", "group_hierarchy"],
    "supported_properties": ["owner_tenant_id", "id"]
  }
}
```

**PDP → PEP Response:**

Tenant constraint is always included:

```json
{
  "decision": true,
  "context": {
    "constraints": [
      {
        "predicates": [
          {
            "op": "eq",
            "property": "owner_tenant_id",
            "value": "T1-uuid"
          },
          {
            "op": "in_group_subtree",
            "property": "id",
            "ancestor_ids": ["FolderA-uuid"]
          }
        ]
      }
    ]
  }
}
```

**SQL:**
```sql
SELECT * FROM tasks
WHERE owner_tenant_id = 'T1-uuid'
  AND CAST(id AS text) IN (
    SELECT resource_id FROM resource_group_membership
    WHERE group_id IN (
      SELECT descendant_id FROM resource_group_closure
      WHERE ancestor_id IN ('FolderA-uuid')
    )
      AND gts_type_id IN (
        SELECT id FROM gts_type
        WHERE schema_id = 'gts.cf.core.tasks.task.v1~'
      )
  )
```

---

#### S16: UPDATE, group membership, PEP has resource_group_membership (reference)

`PUT /tasks/{id}`

User updates a task; PEP has resource_group_membership table. Similar to tenant-based S03, but filtering by group membership.

> **Reference pattern:** Requires `resource_group_membership` in the PEP's database (no projection mechanism exists). For the standard domain service pattern for mutations, see S18.

**Request:**
```http
PUT /tasks/task456-uuid
Authorization: Bearer <token>
Content-Type: application/json

{"status": "completed"}
```

**PEP → PDP Request:**
```json
{
  "subject": {
    "type": "gts.cf.core.security.subject_user.v1~",
    "id": "user123-uuid",
    "properties": { "tenant_id": "T1-uuid" }
  },
  "action": { "name": "update" },
  "resource": {
    "type": "gts.cf.core.tasks.task.v1~",
    "id": "task456-uuid"
  },
  "context": {
    "tenant_context": {
      "mode": "root_only",
      "root_id": "T1-uuid"
    },
    "require_constraints": true,
    "capabilities": ["group_membership"],
    "supported_properties": ["owner_tenant_id", "id"]
  }
}
```

**PDP → PEP Response:**

Tenant constraint is always included:

```json
{
  "decision": true,
  "context": {
    "constraints": [
      {
        "predicates": [
          {
            "op": "eq",
            "property": "owner_tenant_id",
            "value": "T1-uuid"
          },
          {
            "op": "in_group",
            "property": "id",
            "group_ids": ["ProjectA-uuid", "ProjectB-uuid"]
          }
        ]
      }
    ]
  }
}
```

**SQL:**
```sql
UPDATE tasks
SET status = 'completed'
WHERE id = 'task456-uuid'
  AND owner_tenant_id = 'T1-uuid'
  AND CAST(id AS text) IN (
    SELECT resource_id FROM resource_group_membership
    WHERE group_id IN ('ProjectA-uuid', 'ProjectB-uuid')
      AND gts_type_id IN (
        SELECT id FROM gts_type
        WHERE schema_id = 'gts.cf.core.tasks.task.v1~'
      )
  )
```

**Result interpretation:**
- 1 row affected → success
- 0 rows affected → task doesn't exist or not in user's accessible groups → **404**

---

#### S17: UPDATE, group subtree, PEP has closure + membership (reference)

`PUT /tasks/{id}`

User updates a task; PEP has both resource_group_membership and resource_group_closure tables.

> **Reference pattern:** Requires both `resource_group_closure` and `resource_group_membership` in the PEP's database (no projection mechanism exists). For the standard domain service pattern for mutations, see S18.

**Request:**
```http
PUT /tasks/task456-uuid
Authorization: Bearer <token>
Content-Type: application/json

{"status": "completed"}
```

**PEP → PDP Request:**
```json
{
  "subject": {
    "type": "gts.cf.core.security.subject_user.v1~",
    "id": "user123-uuid",
    "properties": { "tenant_id": "T1-uuid" }
  },
  "action": { "name": "update" },
  "resource": {
    "type": "gts.cf.core.tasks.task.v1~",
    "id": "task456-uuid"
  },
  "context": {
    "tenant_context": {
      "mode": "root_only",
      "root_id": "T1-uuid"
    },
    "require_constraints": true,
    "capabilities": ["group_membership", "group_hierarchy"],
    "supported_properties": ["owner_tenant_id", "id"]
  }
}
```

**PDP → PEP Response:**

Tenant constraint is always included:

```json
{
  "decision": true,
  "context": {
    "constraints": [
      {
        "predicates": [
          {
            "op": "eq",
            "property": "owner_tenant_id",
            "value": "T1-uuid"
          },
          {
            "op": "in_group_subtree",
            "property": "id",
            "ancestor_ids": ["FolderA-uuid"]
          }
        ]
      }
    ]
  }
}
```

**SQL:**
```sql
UPDATE tasks
SET status = 'completed'
WHERE id = 'task456-uuid'
  AND owner_tenant_id = 'T1-uuid'
  AND CAST(id AS text) IN (
    SELECT resource_id FROM resource_group_membership
    WHERE group_id IN (
      SELECT descendant_id FROM resource_group_closure
      WHERE ancestor_id IN ('FolderA-uuid')
    )
      AND gts_type_id IN (
        SELECT id FROM gts_type
        WHERE schema_id = 'gts.cf.core.tasks.task.v1~'
      )
  )
```

---

#### S18: GET, group membership, domain service (no membership table)

`GET /tasks/{id}`

Standard domain service pattern for point operations. PEP doesn't have the `resource_group_membership` table (no projection mechanism exists). PDP resolves group membership internally and returns a tenant constraint for defense in depth.

**Request:**
```http
GET /tasks/task456-uuid
Authorization: Bearer <token>
```

**Step 1 — PEP → PDP Request:**
```json
{
  "subject": {
    "type": "gts.cf.core.security.subject_user.v1~",
    "id": "user123-uuid",
    "properties": { "tenant_id": "T1-uuid" }
  },
  "action": { "name": "read" },
  "resource": {
    "type": "gts.cf.core.tasks.task.v1~",
    "id": "task456-uuid"
  },
  "context": {
    "tenant_context": {
      "mode": "root_only",
      "root_id": "T1-uuid"
    },
    "require_constraints": true,
    "capabilities": [],
    "supported_properties": ["owner_tenant_id", "id"]
  }
}
```

**PDP internally:**
1. Resolves resource's group membership (via PIP or own storage)
2. Checks if subject has access to any of those groups
3. Validates tenant access

**PDP → PEP Response:**

PDP returns tenant constraint as defense in depth (group check already done):

```json
{
  "decision": true,
  "context": {
    "constraints": [
      {
        "predicates": [
          {
            "op": "eq",
            "property": "owner_tenant_id",
            "value": "T1-uuid"
          }
        ]
      }
    ]
  }
}
```

**Step 2 — SQL with constraint:**
```sql
SELECT * FROM tasks
WHERE id = 'task456-uuid'
  AND owner_tenant_id = 'T1-uuid'
```

**Result interpretation:**
- 1 row → return task
- 0 rows → **404 Not Found**

**Note:** This is the standard domain service pattern — no projection mechanism exists, so domain services do not have `resource_group_membership`. PDP resolves group membership internally via PIP. For LIST operations, PDP returns explicit resource IDs via `in` predicate (see S19). This pattern works best for point operations (GET, UPDATE, DELETE by ID) where PDP can check a single resource's membership efficiently.

---

#### S19: LIST, group-based filtering, domain service (no group tables)

`GET /tasks`

Standard domain service pattern for LIST operations with group-based access control. PEP has no `resource_group_membership` (no projection mechanism exists) and no `resource_group_closure`. PDP resolves group memberships internally and returns explicit resource IDs.

**Request:**
```http
GET /tasks
Authorization: Bearer <token>
```

**PEP → PDP Request:**
```json
{
  "subject": {
    "type": "gts.cf.core.security.subject_user.v1~",
    "id": "user123-uuid",
    "properties": { "tenant_id": "T1-uuid" }
  },
  "action": { "name": "list" },
  "resource": { "type": "gts.cf.core.tasks.task.v1~" },
  "context": {
    "tenant_context": {
      "mode": "root_only",
      "root_id": "T1-uuid"
    },
    "require_constraints": true,
    "capabilities": [],
    "supported_properties": ["owner_tenant_id", "id"]
  }
}
```

**Note:** PEP declares no group capabilities — no projection mechanism exists, so domain services do not have `resource_group_membership`. PDP must resolve group memberships internally and degrade to explicit IDs.

**PDP → PEP Response:**

PDP knows user has access to FolderA and its subfolders. PDP resolves the hierarchy (via closure) and group memberships (via membership) internally, then returns explicit resource IDs. Tenant constraint is always included:

```json
{
  "decision": true,
  "context": {
    "constraints": [
      {
        "predicates": [
          {
            "op": "eq",
            "property": "owner_tenant_id",
            "value": "T1-uuid"
          },
          {
            "op": "in",
            "property": "id",
            "values": ["task1-uuid", "task2-uuid", "task5-uuid", "task7-uuid"]
          }
        ]
      }
    ]
  }
}
```

**SQL:**
```sql
SELECT * FROM tasks
WHERE owner_tenant_id = 'T1-uuid'
  AND id IN ('task1-uuid', 'task2-uuid', 'task5-uuid', 'task7-uuid')
```

**Trade-off:** PDP must resolve group hierarchy, membership, and map to resource IDs internally. Works well for moderate result sets; may not scale for groups containing thousands of resources. For point operations (GET/UPDATE/DELETE by ID), prefer S18 pattern.

---

### Advanced Patterns

---

#### S20: LIST, tenant subtree and group membership (AND), domain service

`GET /tasks?tenant_subtree=true`

User has access to tasks in their tenant subtree AND in specific projects. Both conditions must be satisfied. Domain service has a `tenant_closure` projection (illustrative: projection is planned, not implemented — only Account Management has `tenant_closure`) but no `resource_group_membership` — PDP degrades group constraint to explicit resource IDs.

**Request:**
```http
GET /tasks?tenant_subtree=true
Authorization: Bearer <token>
```

**PEP → PDP Request:**
```json
{
  "subject": {
    "type": "gts.cf.core.security.subject_user.v1~",
    "id": "user123-uuid",
    "properties": { "tenant_id": "T1-uuid" }
  },
  "action": { "name": "list" },
  "resource": { "type": "gts.cf.core.tasks.task.v1~" },
  "context": {
    "tenant_context": {
      "mode": "subtree",
      "root_id": "T1-uuid"
    },
    "require_constraints": true,
    "capabilities": ["tenant_hierarchy"],
    "supported_properties": ["owner_tenant_id", "id"]
  }
}
```

**PDP → PEP Response:**

Single constraint with multiple predicates (AND semantics). Tenant subtree uses `in_tenant_subtree` (PEP has closure), group constraint is degraded to explicit IDs:

```json
{
  "decision": true,
  "context": {
    "constraints": [
      {
        "predicates": [
          {
            "op": "in_tenant_subtree",
            "property": "owner_tenant_id",
            "root_tenant_id": "T1-uuid"
          },
          {
            "op": "in",
            "property": "id",
            "values": ["task1-uuid", "task3-uuid"]
          }
        ]
      }
    ]
  }
}
```

**SQL:**
```sql
SELECT * FROM tasks
WHERE owner_tenant_id IN (
    SELECT descendant_id FROM tenant_closure
    WHERE ancestor_id = 'T1-uuid'
      AND barrier = 0  -- barrier_mode defaults to "respect"
  )
  AND id IN ('task1-uuid', 'task3-uuid')
```

---

#### S21: LIST, tenant subtree and group subtree, domain service

`GET /tasks?tenant_subtree=true`

User has access to tasks that are owned by tenants in their subtree AND belong to a folder or any of its subfolders. Domain service has `tenant_closure` (illustrative: requires the planned projection — only Account Management has it) but no group tables — PDP resolves group hierarchy and memberships internally.

**Use case:** Manager can see tasks from their department (tenant subtree) that are in the "Q1 Projects" folder or any nested subfolder.

**Request:**
```http
GET /tasks?tenant_subtree=true
Authorization: Bearer <token>
```

**PEP → PDP Request:**
```json
{
  "subject": {
    "type": "gts.cf.core.security.subject_user.v1~",
    "id": "user123-uuid",
    "properties": { "tenant_id": "T1-uuid" }
  },
  "action": { "name": "list" },
  "resource": { "type": "gts.cf.core.tasks.task.v1~" },
  "context": {
    "tenant_context": {
      "mode": "subtree",
      "root_id": "T1-uuid"
    },
    "require_constraints": true,
    "capabilities": ["tenant_hierarchy"],
    "supported_properties": ["owner_tenant_id", "id"]
  }
}
```

**PDP → PEP Response:**

Single constraint with two predicates (AND semantics). Tenant subtree uses `in_tenant_subtree` (PEP has closure); group constraint is degraded to explicit resource IDs (PDP resolved hierarchy + membership internally):

```json
{
  "decision": true,
  "context": {
    "constraints": [
      {
        "predicates": [
          {
            "op": "in_tenant_subtree",
            "property": "owner_tenant_id",
            "root_tenant_id": "T1-uuid"
          },
          {
            "op": "in",
            "property": "id",
            "values": ["task1-uuid", "task2-uuid", "task5-uuid"]
          }
        ]
      }
    ]
  }
}
```

**SQL:**
```sql
SELECT * FROM tasks
WHERE owner_tenant_id IN (
    SELECT descendant_id FROM tenant_closure
    WHERE ancestor_id = 'T1-uuid'
      AND barrier = 0
  )
  AND id IN ('task1-uuid', 'task2-uuid', 'task5-uuid')
```

**Projection tables used:**
- `tenant_closure` — resolves tenant subtree (T1 and all descendants)

**Note:** PDP resolves group hierarchy (via closure) and group membership internally. The domain service only receives degraded `in` predicates with explicit resource IDs. For the equivalent native pattern (RG tables co-located with the service and an opted-in resource type), see S15.

---

#### S22: LIST, multiple access paths (OR)

`GET /tasks`

User has multiple ways to access tasks: (1) via project membership, (2) via explicitly shared tasks.

**Request:**
```http
GET /tasks
Authorization: Bearer <token>
```

**PEP → PDP Request:**
```json
{
  "subject": {
    "type": "gts.cf.core.security.subject_user.v1~",
    "id": "user123-uuid",
    "properties": { "tenant_id": "T1-uuid" }
  },
  "action": { "name": "list" },
  "resource": { "type": "gts.cf.core.tasks.task.v1~" },
  "context": {
    "tenant_context": {
      "mode": "root_only",
      "root_id": "T1-uuid"
    },
    "require_constraints": true,
    "capabilities": [],
    "supported_properties": ["owner_tenant_id", "id"]
  }
}
```

**PDP → PEP Response:**

Multiple constraints (OR semantics). Tenant constraint is included in each path. PDP resolves group memberships internally and returns explicit resource IDs:

```json
{
  "decision": true,
  "context": {
    "constraints": [
      {
        "predicates": [
          {
            "op": "eq",
            "property": "owner_tenant_id",
            "value": "T1-uuid"
          },
          {
            "op": "in",
            "property": "id",
            "values": ["task1-uuid", "task2-uuid", "task3-uuid"]
          }
        ]
      },
      {
        "predicates": [
          {
            "op": "eq",
            "property": "owner_tenant_id",
            "value": "T1-uuid"
          },
          {
            "op": "in",
            "property": "id",
            "values": ["taskshared1-uuid", "taskshared2-uuid"]
          }
        ]
      }
    ]
  }
}
```

**SQL:**
```sql
SELECT * FROM tasks
WHERE (
    owner_tenant_id = 'T1-uuid'
    AND id IN ('task1-uuid', 'task2-uuid', 'task3-uuid')
  )
  OR (
    owner_tenant_id = 'T1-uuid'
    AND id IN ('taskshared1-uuid', 'taskshared2-uuid')
  )
```

---

#### S23: Access denied

`GET /tasks`

User doesn't have permission to access the requested resources.

**Request:**
```http
GET /tasks
Authorization: Bearer <token>
```

**PEP → PDP Request:**
```json
{
  "subject": {
    "type": "gts.cf.core.security.subject_user.v1~",
    "id": "user123-uuid",
    "properties": { "tenant_id": "T1-uuid" }
  },
  "action": { "name": "list" },
  "resource": { "type": "gts.cf.core.tasks.task.v1~" },
  "context": {
    "tenant_context": {
      "mode": "root_only",
      "root_id": "T1-uuid"
    },
    "require_constraints": true,
    "capabilities": ["tenant_hierarchy"],
    "supported_properties": ["owner_tenant_id", "id"]
  }
}
```

**PDP → PEP Response:**
```json
{
  "decision": false,
  "context": {
    "deny_reason": {
      "error_code": "gts.cf.core.errors.err.v1~x.authz.errors.insufficient_permissions.v1",
      "details": "Subject 'user123-uuid' lacks 'list' permission on 'gts.cf.core.tasks.task.v1~' in tenant 'T1-uuid'"
    }
  }
}
```

**PEP Action:**
- No SQL query is executed
- Use `error_code` for programmatic handling (e.g., metrics, error categorization)
- Log `deny_reason` for audit/debugging (includes `error_code` and `details`)
- Return **403 Forbidden** to client without exposing `details`

**Fail-closed principle:** The PEP never executes a database query when `decision: false`. This prevents any data leakage and ensures authorization is enforced before resource access.

**Note on deny_reason:** The `deny_reason` is optional when `decision: false` (the shipped static and tr-authz plugins deny without it). When present, PEP uses `error_code` for programmatic handling and logs `details` for troubleshooting, but returns a generic 403 response to prevent leaking authorization policy details to clients.

---

### Subject Owner-Based Access

PEP supports `owner_id` as a standard resource property for per-subject ownership filtering. These scenarios demonstrate how `owner_id` constraints restrict access to resources owned by a specific user.

**No projection tables** are needed — `owner_id` uses simple `eq` predicates compiled directly to SQL.

**No prefetch** is needed — PDP always knows the subject's identity from `subject.id` in the evaluation request, so it can return `eq(owner_id, subject_id)` without PEP prefetching resource attributes. This is fundamentally different from "without tenant_closure" scenarios (S09–S11), where PEP must prefetch `owner_tenant_id` to tell PDP which specific tenant to validate.

**`tenant_context` is omitted** from these requests. PDP infers the tenant context from `subject.properties.tenant_id` (see [DESIGN.md — tenant_context note](./DESIGN.md#request--response-example)). This is only safe when the subject's home tenant is the intended context; for cross-tenant access or service-to-service flows, supply `tenant_context` explicitly. PDP still returns `eq(owner_tenant_id, ...)` as defense-in-depth to ensure tenant isolation at the SQL level.

---

#### S24: LIST, owner-only access

`GET /tasks`

User requests only their own tasks. PDP restricts access to resources where `owner_id` matches the subject.

**Use case:** Personal task list — "show only my tasks."

**Request:**
```http
GET /tasks
Authorization: Bearer <token>
```

**PEP → PDP Request:**
```json
{
  "subject": {
    "type": "gts.cf.core.security.subject_user.v1~",
    "id": "user123-uuid",
    "properties": { "tenant_id": "T1-uuid" }
  },
  "action": { "name": "list" },
  "resource": { "type": "gts.cf.core.tasks.task.v1~" },
  "context": {
    "require_constraints": true,
    "capabilities": [],
    "supported_properties": ["owner_tenant_id", "id", "owner_id"]
  }
}
```

**PDP → PEP Response:**

Single constraint with two predicates (AND semantics) — tenant isolation (defense-in-depth) plus owner restriction:

```json
{
  "decision": true,
  "context": {
    "constraints": [
      {
        "predicates": [
          {
            "op": "eq",
            "property": "owner_tenant_id",
            "value": "T1-uuid"
          },
          {
            "op": "eq",
            "property": "owner_id",
            "value": "user123-uuid"
          }
        ]
      }
    ]
  }
}
```

**SQL:**
```sql
SELECT * FROM tasks
WHERE owner_tenant_id = 'T1-uuid'
  AND owner_id = 'user123-uuid'
```

---

#### S25: GET, owner-only access

`GET /tasks/{id}`

User requests a specific task; PDP constrains access to resources owned by the subject.

**Use case:** View task details — accessible only if the user owns it.

**Request:**
```http
GET /tasks/task456-uuid
Authorization: Bearer <token>
```

**PEP → PDP Request:**
```json
{
  "subject": {
    "type": "gts.cf.core.security.subject_user.v1~",
    "id": "user123-uuid",
    "properties": { "tenant_id": "T1-uuid" }
  },
  "action": { "name": "read" },
  "resource": {
    "type": "gts.cf.core.tasks.task.v1~",
    "id": "task456-uuid"
  },
  "context": {
    "require_constraints": true,
    "capabilities": [],
    "supported_properties": ["owner_tenant_id", "id", "owner_id"]
  }
}
```

**PDP → PEP Response:**
```json
{
  "decision": true,
  "context": {
    "constraints": [
      {
        "predicates": [
          {
            "op": "eq",
            "property": "owner_tenant_id",
            "value": "T1-uuid"
          },
          {
            "op": "eq",
            "property": "owner_id",
            "value": "user123-uuid"
          }
        ]
      }
    ]
  }
}
```

**SQL:**
```sql
SELECT * FROM tasks
WHERE id = 'task456-uuid'
  AND owner_tenant_id = 'T1-uuid'
  AND owner_id = 'user123-uuid'
```

**Result interpretation:**
- 1 row → return task
- 0 rows → **404 Not Found** (task doesn't exist, wrong tenant, or user doesn't own it)

---

#### S26: UPDATE, owner-only mutation

`PUT /tasks/{id}`

User updates a task; PDP constrains the mutation to resources owned by the subject. The `owner_id` constraint in the WHERE clause provides TOCTOU protection — if ownership changed between check and execution, the update atomically fails.

**Use case:** User can only edit their own tasks.

**Request:**
```http
PUT /tasks/task456-uuid
Authorization: Bearer <token>
Content-Type: application/json

{"status": "done"}
```

**PEP → PDP Request:**
```json
{
  "subject": {
    "type": "gts.cf.core.security.subject_user.v1~",
    "id": "user123-uuid",
    "properties": { "tenant_id": "T1-uuid" }
  },
  "action": { "name": "update" },
  "resource": {
    "type": "gts.cf.core.tasks.task.v1~",
    "id": "task456-uuid"
  },
  "context": {
    "require_constraints": true,
    "capabilities": [],
    "supported_properties": ["owner_tenant_id", "id", "owner_id"]
  }
}
```

**PDP → PEP Response:**
```json
{
  "decision": true,
  "context": {
    "constraints": [
      {
        "predicates": [
          {
            "op": "eq",
            "property": "owner_tenant_id",
            "value": "T1-uuid"
          },
          {
            "op": "eq",
            "property": "owner_id",
            "value": "user123-uuid"
          }
        ]
      }
    ]
  }
}
```

**SQL:**
```sql
UPDATE tasks
SET status = 'done'
WHERE id = 'task456-uuid'
  AND owner_tenant_id = 'T1-uuid'
  AND owner_id = 'user123-uuid'
```

**Result interpretation:**
- 1 row affected → success
- 0 rows affected → **404 Not Found** (task doesn't exist, wrong tenant, or user doesn't own it)

---

#### S27: DELETE, owner-only mutation

`DELETE /tasks/{id}`

DELETE follows the same pattern as UPDATE (S26). PDP returns `eq(owner_id)` + `eq(owner_tenant_id)` constraints, PEP applies them in the DELETE's WHERE clause.

**SQL:**
```sql
DELETE FROM tasks
WHERE id = 'task456-uuid'
  AND owner_tenant_id = 'T1-uuid'
  AND owner_id = 'user123-uuid'
```

**Result interpretation:**
- 1 row affected → success
- 0 rows affected → **404 Not Found** (task doesn't exist, wrong tenant, or user doesn't own it)

TOCTOU protection is identical to S26: if `owner_id` or `owner_tenant_id` changed between check and DELETE, the WHERE clause won't match → 0 rows → **404**.

---

#### S28: CREATE, owner-only

`POST /tasks`

User creates a new task. PEP sets `owner_id` from `SecurityContext.subject_id` — the subject owns the resource they create. PDP validates both `owner_tenant_id` and `owner_id` via constraints, preventing the caller from creating resources assigned to a different user.

**Use case:** User creates a task assigned to themselves.

**Request:**
```http
POST /tasks
Authorization: Bearer <token>
Content-Type: application/json

{"title": "New Task"}
```

**PEP resolves owner from SecurityContext:**

PEP reads `subject_id` (user123-uuid) and `subject_tenant_id` (T1-uuid) from `SecurityContext`. These become `owner_id` and `owner_tenant_id` for the new resource — same pattern as S06 for tenant context.

**PEP → PDP Request:**
```json
{
  "subject": {
    "type": "gts.cf.core.security.subject_user.v1~",
    "id": "user123-uuid",
    "properties": { "tenant_id": "T1-uuid" }
  },
  "action": { "name": "create" },
  "resource": {
    "type": "gts.cf.core.tasks.task.v1~",
    "properties": {
      "owner_tenant_id": "T1-uuid",
      "owner_id": "user123-uuid"
    }
  },
  "context": {
    "require_constraints": true,
    "capabilities": [],
    "supported_properties": ["owner_tenant_id", "id", "owner_id"]
  }
}
```

**PDP → PEP Response:**
```json
{
  "decision": true,
  "context": {
    "constraints": [
      {
        "predicates": [
          {
            "op": "eq",
            "property": "owner_tenant_id",
            "value": "T1-uuid"
          },
          {
            "op": "eq",
            "property": "owner_id",
            "value": "user123-uuid"
          }
        ]
      }
    ]
  }
}
```

**PEP compiles constraints**, then validates the INSERT against them:

**SQL:**
```sql
INSERT INTO tasks (id, owner_tenant_id, owner_id, title, status)
VALUES ('tasknew-uuid', 'T1-uuid', 'user123-uuid', 'New Task', 'pending')
```

**Note:** PDP returns constraints for CREATE using the same flow as other operations. PEP validates that the INSERT's `owner_tenant_id` and `owner_id` match the constraints. This prevents the caller from creating resources in unauthorized tenants or assigned to other users.

---

## TOCTOU Analysis

[Time-of-check to time-of-use (TOCTOU)](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use) is a class of race condition where a security check is performed at one point, but the protected action occurs later when conditions may have changed.

### When TOCTOU Matters

TOCTOU is a security concern only for **mutations** (UPDATE, DELETE). For **reads** (GET, LIST), there's no security violation if the resource changes between check and response — the client receives data they had access to at query time.

| Operation | TOCTOU Concern | Why |
|-----------|----------------|-----|
| GET | ❌ No | Read returns point-in-time snapshot; no state change |
| LIST | ❌ No | Same as GET — read-only |
| UPDATE | ✅ Yes | Must ensure authorization at mutation time |
| DELETE | ✅ Yes | Must ensure authorization at mutation time |
| CREATE | ❌ No | No existing resource to race against |

### How Each Scenario Handles TOCTOU

**Tenant-based scenarios:**

| Scenario | Operation | Closure | Constraint | TOCTOU Protection |
|----------|-----------|---------|------------|-------------------|
| S01-S04, S07 | LIST/GET/UPDATE/DELETE | ✅ | `in_tenant_subtree` | ✅ Atomic SQL check |
| S09 | GET | ❌ | `eq` (prefetched) | N/A (read-only) |
| S10, S11 | UPDATE/DELETE | ❌ | `eq` (prefetched) | ✅ Atomic SQL check |
| S05, S06, S12 | CREATE | N/A | `eq` (from PDP) | N/A (no existing resource) |

**Resource group scenarios (reference — require membership table):**

| Scenario | Operation | Constraint | TOCTOU Protection |
|----------|-----------|------------|-------------------|
| S14, S15 | LIST | `in_group` / `in_group_subtree` | ✅ Atomic SQL check |
| S16, S17 | UPDATE | `in_group` / `in_group_subtree` | ✅ Atomic SQL check |

**Resource group scenarios (domain services — standard, no membership table):**

| Scenario | Operation | Constraint | TOCTOU Protection |
|----------|-----------|------------|-------------------|
| S18 | GET | `eq` (tenant, PDP resolves group internally) | N/A (read-only) |
| S19 | LIST | `in` (explicit resource IDs from PDP) | N/A (read-only) |
| S20, S21 | LIST | `in_tenant_subtree` + `in` (explicit IDs) | N/A (read-only) |

**Subject owner-based scenarios:**

| Scenario | Operation | Constraint | TOCTOU Protection |
|----------|-----------|------------|-------------------|
| S24 | LIST | `eq` (owner) | N/A (read-only) |
| S25 | GET | `eq` (owner) | N/A (read-only) |
| S26 | UPDATE | `eq` (owner) | ✅ Atomic SQL check |
| S27 | DELETE | `eq` (owner) | ✅ Atomic SQL check |
| S28 | CREATE | `eq` (owner) | N/A (no existing resource) |

### Key Insight: Prefetch + Constraint for Mutations

Without closure tables, mutations (UPDATE/DELETE) use a two-step pattern:

1. **Prefetch:** PEP reads `owner_tenant_id = 'T2-uuid'` from database
2. **PDP check:** PDP validates T2 is accessible, returns `eq: owner_tenant_id = 'T2-uuid'`
3. **SQL execution:** `UPDATE tasks SET ... WHERE id = 'X' AND owner_tenant_id = 'T2-uuid'`
4. **If tenant changed:** WHERE clause won't match → 0 rows affected → 404

The constraint acts as a [compare-and-swap](https://en.wikipedia.org/wiki/Compare-and-swap) mechanism — if the value changed between check and use, the operation atomically fails.

**For reads (S09):** PEP prefetches the resource, asks PDP with `require_constraints: false`, and returns the prefetched data if `decision: true` with no constraints. If constraints are returned, PEP falls back to a scoped re-read.

---

## tr-authz-plugin Decision Matrix

The **`tr-authz-plugin`** implements tenant-based access enforcement backed by `TenantResolverClient`. It does not depend on `resource-group-sdk` directly — all hierarchy queries go through the Tenant Resolver.

This section enumerates the 8 decision rules (R1–R8) that govern how `Service::evaluate` translates an incoming request into an access predicate. They are implemented in `gears/system/authz-resolver/plugins/tr-authz-plugin/src/domain/service.rs`.

Example hierarchy used throughout:

```
r (root)
└── t1 (partner)
    └── t2 (partner)
        ├── t3 (customer)
        └── t4 (customer)
```

### Inputs

The algorithm branches on three orthogonal axes derived from `EvaluationRequest`:

| Axis | Value | Source |
|------|-------|--------|
| **Kind of request** | single-resource / list | `resource.id` is present / absent |
| **Explicit target tenant** | specified / absent | `context.tenant_context.root_id` |
| **Scope mode** | `root_only` / `subtree` (default) | `context.tenant_context.mode` |

Additional required values:
- `subject.properties.tenant_id` — the acting subject's tenant (mandatory; deny if missing)
- `resource.properties.owner_tenant_id` — required for single-resource rules (R1–R4) when `resource.id` is present; deny if missing
- `is_parent(ancestor, descendant)` — TR-backed helper returning `true` if `descendant` is `ancestor` or any descendant of `ancestor` in the tenant tree

### Decision Table

| Rule | `resource.id` | `root_id` | `mode` | Access check | Returned predicate |
|------|---------------|-----------|--------|--------------|--------------------|
| R1 | present | specified | `root_only` | `owner_tenant_id == root_id` ∧ `is_parent(subject.tenant_id, root_id)` | `IN([owner_tenant_id])` |
| R2 | present | specified | `subtree` | `is_parent(root_id, owner_tenant_id)` ∧ `is_parent(subject.tenant_id, root_id)` | `IN([owner_tenant_id])` |
| R3 | present | absent | `root_only` | `owner_tenant_id == subject.tenant_id` | `IN([owner_tenant_id])` |
| R4 | present | absent | `subtree` | `is_parent(subject.tenant_id, owner_tenant_id)` | `IN([owner_tenant_id])` |
| R5 | absent | specified | `root_only` | `is_parent(subject.tenant_id, root_id)` | `IN([root_id])` |
| R6 | absent | specified | `subtree` | `is_parent(subject.tenant_id, root_id)` | `IN(get_descendants(root_id))` |
| R7 | absent | absent | `root_only` | always allowed (subject scope) | `IN([subject.tenant_id])` |
| R8 | absent | absent | `subtree` | always allowed (subject scope) | `IN(get_descendants(subject.tenant_id))` |

Semantics of `is_parent(a, b)`: `b` is `a` itself or any descendant of `a`. Wherever the access check fails, the plugin returns **deny** (fail-closed). Where a helper call (e.g. `get_descendants`) errors out, the plugin also denies.

The tenant predicate returned by every rule is an `in` predicate on `owner_tenant_id` of the target resource table (single-tenant rules emit a one-element `in`, not `eq`); R5/R7 narrow the scope to exactly one tenant, while R6/R8 expand it to a full subtree. On allow, the plugin also appends group predicates to the same constraint when the request's resource properties carry them: `in_group` on `id` for `group_ids` (requires the `group_membership` capability) and `in_group_subtree` on `id` for `ancestor_group_ids` (requires `group_membership` and `group_hierarchy`). A group property that is malformed, empty, or sent without the required capabilities denies the request.

### R1 — Single-resource, explicit target tenant, root_only

**Use case:** Partner's admin reads one task that belongs to its customer, scoped strictly to that customer (no subtree).

```http
GET /tasks/028bedcd-6f7f-4158-89c1-acbb60caddff?tenant=t2&tenant_mode=root_only
Subject tenant: t1
```

**Check:** `resource.owner_tenant_id == t2` AND `is_parent(t1, t2)` — i.e., the subject's tenant must be an ancestor of the declared target tenant, and the resource must actually belong to that target.

**Predicate:** `IN(owner_tenant_id, [t2])`

### R2 — Single-resource, explicit target tenant, subtree (default)

**Use case:** Partner's admin reads one task from somewhere in its customer's subtree.

```http
GET /tasks/028bedcd-6f7f-4158-89c1-acbb60caddff?tenant=t2
Subject tenant: t1
```

**Check:** `is_parent(t2, resource.owner_tenant_id)` AND `is_parent(t1, t2)` — the resource must lie within the target's subtree, and the subject must be an ancestor of the target.

**Predicate:** `IN(owner_tenant_id, [resource.owner_tenant_id])` (constraint is still pinned to the concrete resource tenant to make the SQL deterministic)

### R3 — Single-resource, no target tenant, root_only

**Use case:** A customer-level user reads their own task without crossing subtree boundaries.

```http
GET /tasks/028bedcd-6f7f-4158-89c1-acbb60caddff?tenant_mode=root_only
Subject tenant: t3
```

**Check:** `resource.owner_tenant_id == subject.tenant_id`.

**Predicate:** `IN(owner_tenant_id, [subject.tenant_id])`

### R4 — Single-resource, no target tenant, subtree (default)

**Use case:** Partner admin reads one task anywhere in its own subtree.

```http
GET /tasks/028bedcd-6f7f-4158-89c1-acbb60caddff
Subject tenant: t1
```

**Check:** `is_parent(subject.tenant_id, resource.owner_tenant_id)`.

**Predicate:** `IN(owner_tenant_id, [resource.owner_tenant_id])`

### R5 — List, explicit target tenant, root_only

**Use case:** Partner admin lists tasks that belong *strictly* to its customer tenant (no sub-partners, no sub-customers).

```http
GET /tasks?tenant=t2&tenant_mode=root_only
Subject tenant: t1
```

**Check:** `is_parent(t1, t2)`.

**Predicate:** `IN(owner_tenant_id, [t2])` — one tenant only.

### R6 — List, explicit target tenant, subtree (default)

**Use case:** Partner admin lists everything in its customer's subtree.

```http
GET /tasks?tenant=t2
Subject tenant: t1
```

**Check:** `is_parent(t1, t2)`.

**Action:** resolve `get_descendants(t2)` via TR, following `tenant_context.barrier_mode` (default `respect`) and filtered by `tenant_context.tenant_status` when supplied.

**Predicate:** `IN(owner_tenant_id, descendants(t2))`

### R7 — List, no target tenant, root_only

**Use case:** Customer-level user lists their own tasks only.

```http
GET /tasks?tenant_mode=root_only
Subject tenant: t3
```

**Check:** none beyond identity (the subject is always allowed to list within their own tenant).

**Predicate:** `IN(owner_tenant_id, [subject.tenant_id])`

### R8 — List, no target tenant, subtree (default)

**Use case:** Partner admin lists tasks across their whole subtree.

```http
GET /tasks
Subject tenant: t1
```

**Check:** none beyond identity.

**Action:** resolve `get_descendants(subject.tenant_id)` via TR, with the same `barrier_mode` and `tenant_status` handling as R6.

**Predicate:** `IN(owner_tenant_id, descendants(subject.tenant_id))`

### Required Helpers

The matrix relies on two core capabilities provided by `tr-authz-plugin`:

1. **`is_parent(ancestor, descendant)`** — reflexive ancestor check, implemented in `tr-authz-plugin` as `Service::is_in_subtree` on top of `TenantResolverClient::is_ancestor` (with the reflexive `anchor == candidate` short-circuit returning `true`).
2. **Reading `context.tenant_context.mode`** — `root_only` / `subtree` selection used to route R1–R8 branches; surfaced through `authz-resolver-sdk::TenantMode` on `TenantContext`.

Test all 8 rules and fail-closed paths (missing subject tenant, `is_parent` returns false, TR error). If the resolved descendants set is empty, R6/R8 deny (fail-closed) rather than return an empty constraint.

---

## References

- [DESIGN.md](./DESIGN.md) — Core authorization design
- [TENANT_MODEL.md](./TENANT_MODEL.md) — Tenant topology, barriers, closure tables
- [RESOURCE_GROUP_MODEL.md](./RESOURCE_GROUP_MODEL.md) — Resource group topology, membership, hierarchy
- [TOCTOU - Wikipedia](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use)
- [Race Conditions - PortSwigger](https://portswigger.net/web-security/race-conditions)
- [AWS Multi-tenant Authorization](https://docs.aws.amazon.com/prescriptive-guidance/latest/saas-multitenant-api-access-authorization/introduction.html)
