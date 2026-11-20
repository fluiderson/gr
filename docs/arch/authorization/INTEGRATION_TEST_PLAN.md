<!-- Created: 2026-04-07 by Constructor Tech -->
<!-- Updated: 2026-04-20 by Constructor Tech -->

# AuthZ + Resource Group Integration Test Plan

Design-time test plan for verifying the RG ↔ AuthZ interaction locally in cf-gears-server. Covers three phases: tenant scoping (`p1`), group-based predicates (`p1`), and MTLS bypass (`p2` — deferred, not implemented yet).

For background on how AuthZ uses RG data, see [RESOURCE_GROUP_MODEL.md](./RESOURCE_GROUP_MODEL.md). For concrete SQL-level scenarios, see [AUTHZ_USAGE_SCENARIOS.md](./AUTHZ_USAGE_SCENARIOS.md) scenarios S14–S21.

---

## Current State

| Component | Status | Notes |
|-----------|--------|-------|
| RG Gear | **Done** | `ResourceGroupClient` + `ResourceGroupReadHierarchy` traits, `get_group_descendants` / `get_group_ancestors` endpoints |
| AuthZ Resolver | Existing | Plugin discovery, `PolicyEnforcer`, `AccessScope` → SecureORM already exist in the platform |
| Static AuthZ Plugin | Existing | Returns `In(owner_tenant_id, [tid])`, plus `InTenantSubtree` when `tenant_hierarchy` is advertised — tenant predicates only. Group predicates come from `tr-authz-plugin` |
| **PolicyEnforcer in RG handlers** | **Done** | `GroupService` calls `enforcer.access_scope()` for all operations |
| **AccessScope → SecureORM in RG repo** | **Done** | `GroupRepository.list_groups`, `find_by_id`, `get_descendants`, `get_ancestors` accept `&AccessScope` |
| **Rust integration tests** | **Done** | RG crate tests (incl. `authz_integration_test.rs`, `tenant_scoping_test.rs`, `tenant_filtering_db_test.rs`) + 35 tr-authz-plugin tests |
| **E2E HTTP tests** | **Partial** | 13 RG e2e tests in `test_integration_seams.py` (static-authz). The `tr-authz` e2e profile is TEMPORARILY reduced to a feature set without `resource-group` / `tr-authz` / `tenant-resolver-rg` (startup-ordering crash, [#4568](https://github.com/constructorfabric/gears-rust/issues/4568)), so the AuthZ → TR → RG chain is not exercised end-to-end |
| **Tenant provisioning** | **Done** | Tenant groups are identified by GTS type prefix (`TENANT_RG_TYPE_PATH`): `tenant_id = group.id` for tenant groups, otherwise inherited from the caller / parent (`GroupService` create path) |
| Group predicates (`in_group`, `in_group_subtree`) | **Done** | PEP compiler + SecureORM compile them; `tr-authz-plugin` emits them from `group_ids` / `ancestor_group_ids` resource properties |

---

## Planned File Layout

```
testing/e2e/suites/resource_group/         ← E2E tests (pytest, HTTP against running server)
  conftest.py                              ← Fixtures: base_url, auth headers, type/group factories
  test_integration_seams.py                ← HTTP integration seams, incl. tenant filter + cross-tenant isolation

gears/system/resource-group/
  resource-group/tests/                    ← Rust integration tests (in-process, no HTTP)
    authz_integration_test.rs              ← PolicyEnforcer + mock AuthZ: 9 tests
    tenant_scoping_test.rs                 ← AccessScope scoping: 10 tests
    tenant_filtering_db_test.rs            ← full chain with real SQLite DB: 8 tests (6 tenant + 2 group-based)
```

Follows existing project conventions: `testing/e2e/suites/{gear}/` for HTTP-level tests (see `oagw/`, `mini_chat/`, `types_registry/`), `gears/.../tests/` for Rust in-process tests.

---

## Prerequisites

- Rust stable (MSRV 1.95.0)
- Docker (for PostgreSQL)
- `protoc` installed (`brew install protobuf` on macOS)

### Start PostgreSQL

```bash
docker run -d --name rg-postgres \
  -e POSTGRES_USER=cf_gears \
  -e POSTGRES_PASSWORD=cf_gears \
  -e POSTGRES_DB=resource_group \
  -p 5433:5432 postgres:16-alpine
```

### Server Configuration

In `config/quickstart.yaml`, the resource-group gear requires PostgreSQL:

```yaml
gears:
  resource-group:
    database:
      dsn: "postgres://cf_gears:cf_gears@127.0.0.1:5433/resource_group"
      pool:
        max_conns: 5
        acquire_timeout: "30s"
    config: {}
```

### Build and Run

```bash
# Without AuthZ (dev mode, auth_disabled: true)
cargo run --bin cf-gears-server -- --config config/quickstart.yaml run

# With AuthZ (auth_disabled: false + static plugins)
cargo run --bin cf-gears-server \
  --features static-authn,static-authz \
  -- --config config/quickstart.yaml run
```

### Target Test Commands

```bash
# Rust integration tests (no server/DB required)
cargo test -p cf-gears-resource-group --test authz_integration_test --test tenant_scoping_test --test tenant_filtering_db_test

# E2E tests (requires running server + PostgreSQL)
E2E_BASE_URL=http://localhost:8087 pytest testing/e2e/suites/resource_group/ -v
```

---

## Phase 1: Tenant Scoping via PolicyEnforcer _(Implemented)_

**Goal**: Verify that RG endpoints apply `AccessScope` from AuthZ pipeline, filtering results by `tenant_id` from `SecurityContext`.

### Target implementation summary

The intended AuthZ → RG chain is:

1. **Gear init** (`gear.rs`): resolves `dyn AuthZResolverApi` from ClientHub, creates `PolicyEnforcer`
2. **GroupService** (`group_service.rs`): receives `PolicyEnforcer`; all CRUD methods (`list_groups`, `get_group`, `update_group`, `delete_group`, `get_group_descendants`, `get_group_ancestors`) call `enforcer.access_scope(&ctx, &RG_GROUP_RESOURCE, action, resource_id)`
3. **GroupRepository** (`group_repo.rs`): `list_groups`, `find_by_id`, `get_descendants`, `get_ancestors` accept `&AccessScope` and pass it to `SecureORM` via `.secure().scope_with(scope)`
4. **Handlers** (`handlers/groups.rs`): pass `&ctx` to service methods (no longer `_ctx`)
5. **Error handling** (`error.rs`): `DomainError::AccessDenied` → HTTP 403

### Target AuthZ flow

```
Request → API Gateway (AuthN) → SecurityContext{tenant=T1}
  → RG Handler(list_groups) → GroupService.list_groups(&ctx, &query)
    → PolicyEnforcer.access_scope(&ctx, RG_GROUP_RESOURCE, "list", None)
      → Static AuthZ Plugin → decision=true, constraints=[In(owner_tenant_id, [T1])]
    → AccessScope{owner_tenant_id IN (T1)}
    → GroupRepository.list_groups(&conn, &scope, &query)
      → SecureORM → WHERE tenant_id IN ('T1')
  → Response: groups from T1 only
```

### Rust integration tests (25 tests)

**`authz_integration_test.rs`** (9 tests — mock AuthZ, no DB):
- `enforcer_tenant_scoping_produces_correct_access_scope` — mock PDP → correct scope
- `enforcer_different_tenants_get_different_scopes` — tenant isolation at scope level
- `enforcer_deny_all_returns_denied_error` — deny flow
- `enforcer_allow_all_no_constraints_returns_allow_all` — unconstrained path
- `enforcer_allow_all_with_required_constraints_fails` — fail-closed
- `enforcer_passes_resource_id_to_pdp` — request params verification
- `enforcer_works_for_all_crud_actions` — all 5 CRUD actions
- `full_chain_list_groups_calls_enforcer_with_correct_params` — capturing mock verifies PDP receives correct params
- `full_chain_deny_all_blocks_list_groups` — deny-all PDP blocks operation

**`tenant_scoping_test.rs`** (10 tests — AccessScope shape, no DB):
- AccessScope construction, isolation, `tenant_only()`, `deny_all()`, `for_resource()`

**`tenant_filtering_db_test.rs`** (6 tests — **full chain with real SQLite DB**):
- `tenant_isolation_list_groups` — two tenants create groups, each sees only own via `WHERE tenant_id IN (...)`
- `tenant_isolation_get_group_cross_tenant_invisible` — cross-tenant `get_group` → not found
- `tenant_isolation_hierarchy_scoped` — hierarchy filtered by tenant scope
- `tenant_isolation_update_cross_tenant_blocked` — cross-tenant `update_group` → blocked
- `tenant_isolation_update_cross_tenant_is_not_an_existence_oracle` — cross-tenant update answers the same as a missing group
- `tenant_isolation_delete_cross_tenant_blocked` — cross-tenant `delete_group` → blocked; own-tenant delete succeeds

### E2E HTTP tests (13 tests)

**`test_integration_seams.py`** (the only RG e2e test file; tenant scoping is covered by the seams below):
- `test_authz_tenant_filter_applied` — SecurityContext produces the correct tenant filter
- `test_cross_tenant_invisible` — tenant boundary enforced
- `test_route_smoke_all_endpoints`, `test_dto_roundtrip_group_json_shape`, `test_hierarchy_closure`, `test_move_closure_rebuild`, `test_force_delete_cascade`, `test_error_response_rfc9457`, `test_pagination_cursor_roundtrip`, `test_membership_filter_wiring`, `test_hierarchy_depth_filter_wiring`, `test_barrier_metadata_in_descendants`, `test_membership_quoted_uuid_and_gts_filter_sql` — other RG HTTP seams

---

## Phase 2: Group-Based Predicates _(Implemented)_

**Goal**: `InGroup` / `InGroupSubtree` predicates compile to SQL subqueries against `resource_group_membership` and `resource_group_closure` tables.

### Target implementation summary

1. **Predicate types** (`authz-resolver-sdk/src/constraints.rs`): add `InGroupPredicate` (group_ids) and `InGroupSubtreePredicate` (ancestor_ids) to `Predicate` enum with serde support (`"op":"in_group"`, `"op":"in_group_subtree"`)

2. **ScopeFilter variants** (`toolkit-security/src/access_scope.rs`): `InGroupScopeFilter`, `InGroupSubtreeScopeFilter` carry property + group/ancestor UUIDs. Well-known table constants in the `rg_tables` module (`toolkit-db/src/secure/schema.rs`: `MEMBERSHIP_TABLE`, `CLOSURE_TABLE`, `GTS_TYPE_TABLE`, column names)

3. **PEP compiler** (`authz-resolver-sdk/src/pep/compiler.rs`): compiles `InGroup`/`InGroupSubtree` predicates into type-qualified `ScopeFilter` variants via `json_values_to_uuid_scope_values` + `ScopeFilter::in_group_typed` / `in_group_subtree_typed` (the member type is the resource type's canonical GTS name)

4. **SecureORM** (`toolkit-db/src/secure/cond.rs`): `build_constraint_condition` generates subquery SQL:
   - `InGroup` → `CAST(col AS text) IN (SELECT resource_id FROM resource_group_membership WHERE group_id IN (...) AND gts_type_id IN (SELECT id FROM gts_type WHERE schema_id = <member type>))`
   - `InGroupSubtree` → `CAST(col AS text) IN (SELECT resource_id FROM resource_group_membership WHERE group_id IN (SELECT descendant_id FROM resource_group_closure WHERE ancestor_id IN (...)) AND gts_type_id IN (SELECT id FROM gts_type WHERE schema_id = <member type>))`

### SQL generated (S14 scenario)

```sql
WHERE owner_tenant_id IN ('T1')
  AND CAST(id AS text) IN (
    SELECT resource_id FROM resource_group_membership
    WHERE group_id IN ('ProjectA-uuid')
      AND gts_type_id IN (
        SELECT id FROM gts_type
        WHERE schema_id = 'gts.cf.core.tasks.task.v1~'
      )
  )
```

### Tests

**`constraints_tests.rs`** (unit tests): serialization roundtrip for InGroup, InGroupSubtree, mixed constraint

**`compiler_tests.rs`** (unit tests): InGroup → InGroup filter, InGroupSubtree → InGroupSubtree filter, tenant + InGroup combined. Empty `In` / `InGroup` / `InGroupSubtree` sets are valid selections that match nothing; only an all-empty scope becomes `ScopeMatchesNothing` (unless `allow_empty_scope` is set)

**`cond.rs`** (unit tests): InGroup subquery condition, InGroupSubtree nested subquery, tenant + InGroup AND condition

**`tenant_filtering_db_test.rs`** (2 DB tests):
- `group_based_in_group_predicate_against_groups_fails_closed` — mock AuthZ with InGroup + tenant against `RG_GROUP_RESOURCE` → typed unadvertised-capability compile error (the enforcer has table-level group capability, but the group resource does not opt in to membership predicates, so the capability is suppressed and an unsolicited native predicate is rejected fail-closed)
- `group_based_membership_data_correctly_stored` — full S14 data: ProjectA/B, task memberships, verify isolation

### What remains for production use

- **RG-aware AuthZ plugin**: static-authz-plugin returns only tenant predicates (`In`, `InTenantSubtree`); tr-authz-plugin emits `InGroup`/`InGroupSubtree` only from caller-supplied `group_ids` / `ancestor_group_ids`. A real plugin needs to resolve user→group access from an external policy source and emit `InGroup`/`InGroupSubtree` predicates
- **Domain entity integration**: no projection mechanism exists; native group predicates compile only where the RG tables are present in the PEP's database (the RG gear's own database, or a shared-database deployment), and no gear opts in to them. A planned (not implemented) projection would let consuming gears project `resource_group` + `resource_group_closure` for hierarchy queries; `resource_group_membership` (with `gts_type`) projection should only be added when profiling confirms the two-request pattern (RG Membership API → domain service) causes unacceptable latency — this table is 10×+ larger than other projections. In a monolith with a shared DB, no projections are needed at all. By default, domain services rely on PDP capability degradation: PDP resolves group memberships and returns explicit resource IDs via `in` predicates

---

## Phase 3: MTLS Authentication Mode (`p2` — deferred, not implemented yet)

> **Status: `p2` — designed, not implemented yet.** Phase 3 is reserved
> for the future microservice split that moves the AuthZ plugin out of
> the RG process. Do not run/implement this phase in the current
> iteration; the in-process `ResourceGroupReadHierarchy` path covers the
> AuthZ ↔ RG dependency in the monolith.

**Goal**: Verify that AuthZ plugin can read RG hierarchy via MTLS-authenticated request (microservice deployment mode), bypassing AuthZ evaluation.

### Target implementation summary

1. **MTLS routing logic** (`auth.rs`): `determine_auth_mode()` should check client CN + endpoint allowlist → `AuthMode::Mtls` or `AuthMode::Jwt`, using `MtlsConfig`, `AllowedEndpoint`, and path pattern matching.

2. **Rust unit tests** (`auth.rs`): 12 tests covering JWT fallback, MTLS allowed/rejected, edge cases (empty CN, PUT to hierarchy, multiple clients/endpoints, DELETE blocked).

3. **E2E test plan** (`test_mtls_auth.py`): 4 tests with `pytest.skip` when cert infrastructure unavailable:
   - `test_mtls_allowed_endpoint_hierarchy_200`
   - `test_mtls_disallowed_endpoint_post_groups_403`
   - `test_jwt_hierarchy_full_authz`
   - `test_mtls_invalid_cert_cn_rejected`

### What remains for production deployment

- Certificate generation (CA + client certs)
- API Gateway TLS termination configuration (forward client CN header)
- E2E test execution requires cert infrastructure (`E2E_MTLS_CERT_DIR`)

#### 3.1 Certificate infrastructure

Generate self-signed certs for dev:

```bash
# CA
openssl req -x509 -newkey rsa:2048 -keyout ca-key.pem -out ca.pem -days 365 -nodes \
  -subj "/CN=rg-mtls-ca"

# AuthZ plugin client cert
openssl req -newkey rsa:2048 -keyout plugin-key.pem -out plugin.csr -nodes \
  -subj "/CN=authz-resolver-plugin"
openssl x509 -req -in plugin.csr -CA ca.pem -CAkey ca-key.pem -out plugin.pem -days 365
```

#### 3.2 RG MTLS configuration

```yaml
gears:
  resource-group:
    config:
      mtls:
        ca_cert: "certs/ca.pem"
        allowed_clients: ["authz-resolver-plugin"]
        allowed_endpoints:
          - method: GET
            path: "/api/resource-group/v1/groups/{group_id}/descendants"
          - method: GET
            path: "/api/resource-group/v1/groups/{group_id}/ancestors"
```

#### 3.3 API Gateway TLS termination

Configure API Gateway to forward client certificate CN header to RG gear for MTLS mode detection.

### Test scenario

```bash
# MTLS request to allowed endpoint (descendants) — AuthZ bypassed
curl --cert plugin.pem --key plugin-key.pem --cacert ca.pem \
  https://127.0.0.1:8087/cf/resource-group/v1/groups/{group_id}/descendants
# Expected: 200 OK with descendants data

# MTLS request to allowed endpoint (ancestors) — AuthZ bypassed
curl --cert plugin.pem --key plugin-key.pem --cacert ca.pem \
  https://127.0.0.1:8087/cf/resource-group/v1/groups/{group_id}/ancestors
# Expected: 200 OK with ancestors data

# MTLS request to disallowed endpoint (POST groups) — rejected
curl --cert plugin.pem --key plugin-key.pem --cacert ca.pem \
  -X POST https://127.0.0.1:8087/cf/resource-group/v1/groups
# Expected: 403 Forbidden

# JWT request to descendants endpoint — full AuthZ applied
curl -H "Authorization: Bearer test" \
  http://127.0.0.1:8087/cf/resource-group/v1/groups/{group_id}/descendants
# Expected: 200 OK with AuthZ-scoped results
```

### Verification

- MTLS + allowed endpoint → 200, no AuthZ evaluation in logs
- MTLS + disallowed endpoint → 403
- JWT + same endpoint → 200, AuthZ evaluation logged
- Invalid cert CN → 403

---

## E2E Test Hierarchy Fixture (AuthZ plugins)

E2E tests using AuthZ plugins (profile `tr-authz` in `testing/e2e/suites/resource_group/e2e.yaml`, applied over `config/e2e-local.yaml`) require a pre-seeded tenant hierarchy. `conftest.py` provides only the session-scoped, autouse `_seed_root_tenants` fixture (direct SQLite insert of one tenant type and two root tenant groups, `TENANT_A_ID` / `TENANT_B_ID`); each test builds its own groups through the `create_type` / `create_group` factories.

> **Profile status:** the `tr-authz` profile is TEMPORARY-reduced to a feature set that excludes `resource-group`, `tr-authz` and `tenant-resolver-rg` (startup-ordering crash, [#4568](https://github.com/constructorfabric/gears-rust/issues/4568)), so the AuthZ → TR → RG chain is not exercised until it is restored.

**Available AuthZ plugins:**
- `tr-authz-plugin` (priority 90 in the `tr-authz` profile; `rg-tr-plugin` priority 10) — resolves tenants via `TenantResolverClient` (recommended, no direct RG dependency)

### Fixture: `tenant_hierarchy`

> **Not implemented.** No `tenant_hierarchy` fixture exists in `testing/e2e/suites/resource_group/conftest.py`; the hierarchy and setup steps below are the planned design.

```
T1 (root tenant, tenant type, can_be_root=true, token-a subject_tenant_id)
├── T_normal (child tenant, tenant type)
├── T_barrier (tenant with metadata.self_managed=true, tenant type)
│   └── T_behind (child of barrier, tenant type)
└── Dept1 (department, non-tenant type, can_be_root=false, inherits T1 tenant_id)

T2 (root tenant, token-b subject_tenant_id)
```

Tenant-type recognition is code-prefix-driven: any GTS type whose path starts with `TENANT_RG_TYPE_PATH` (`gts.cf.core.rg.type.v1~cf.core._.tenant.v1~`) creates a new tenant scope for its instances.

**Setup steps** (all via REST API, executed once per session):

1. Create tenant type (code starts with `TENANT_RG_TYPE_PATH`, `can_be_root=true`, `allowed_parent_types=[self]`)
2. Create department type (code outside the tenant prefix, `can_be_root=false`, `allowed_parent_types=[tenant_type]`)
3. **Seed T1 root tenant** directly in the DB backend used by the tr-authz overlay — SQLite in CI/e2e; in production deployments the same seeding query runs against the configured SQL-compatible backend (PostgreSQL by default). `id` = token-a `subject_tenant_id`. Root tenants are created via DB seeding, not API.
4. `POST /groups` -- T_normal (parent=T1) -- `tenant_id = T_normal.id`
5. `POST /groups` -- T_barrier (parent=T1, metadata=`{"self_managed": true}`) -- `tenant_id = T_barrier.id`
6. `POST /groups` -- T_behind (parent=T_barrier) -- `tenant_id = T_behind.id`
7. `POST /groups` -- Dept1 (parent=T1, dept type) -- `tenant_id = T1.id` (inherited, non-tenant type)
8. **Seed T2 root tenant** directly in the same DB backend (SQLite in CI/e2e; PostgreSQL in production deployments). `id` = token-b `subject_tenant_id`.

**Prerequisites**:
- Tenant provisioning (tenant-type prefix, implemented): sub-tenant groups set `tenant_id = group.id` when their type code starts with `TENANT_RG_TYPE_PATH`
- Root tenants seeded in DB via the `_seed_root_tenants` conftest fixture (direct SQLite)

### Test coverage using fixture

| Test | Fixture data used | Verifies | Status |
|------|-------------------|----------|--------|
| Barrier metadata in descendants | T1, T_barrier, T_behind | RG returns barrier data without filtering | Implemented as `test_barrier_metadata_in_descendants` (builds its own groups) |
| AuthZ tenant filter | T1, Dept1 | AuthZ plugin resolves hierarchy, scopes correctly | Implemented as `test_authz_tenant_filter_applied` (own type/group, token A) |
| Cross-tenant invisible | T1, T2 | T2 cannot see T1 data via AuthZ plugin | Implemented as `test_cross_tenant_invisible` (own type/group, tokens A/B) |
| Barrier exclusion from scope | T1, T_barrier, T_behind | AuthZ plugin excludes barrier subtree from AccessScope | Not implemented |
| Sub-tenant provisioning | T_normal | Verify `tenant_id == group.id` for sub-tenants | Not implemented |
| Normal group inherits tenant | Dept1 | Verify `tenant_id == parent.tenant_id` | Not implemented |

### Running

```bash
# Build with both authz plugins
make build

# Run RG + AuthZ e2e tests (uses whichever authz plugin has higher priority)
make e2e-tr-authz

# Or manually (applies the tr-authz profile, then runs the RG subset):
python3 tools/scripts/run_e2e.py --suite resource-group --profile tr-authz
```

---

## Effort Estimate

| Phase | Scope | Effort | Priority | Status |
|-------|-------|--------|----------|--------|
| Phase 1 | Tenant scoping via PolicyEnforcer | 2–3 hours | `p1` | **Done** |
| Phase 2 | Group predicates (in_group/in_group_subtree) | 1–2 days | `p1` | **Done** |
| Phase 3 | MTLS verification | 2–3 hours | `p2` | **Deferred — not implemented yet** |

---

## References

- [RESOURCE_GROUP_MODEL.md](./RESOURCE_GROUP_MODEL.md) — How AuthZ uses RG data
- [AUTHZ_USAGE_SCENARIOS.md](./AUTHZ_USAGE_SCENARIOS.md) — SQL-level scenarios (S14–S21 for groups)
- [RG DESIGN](../../../gears/system/resource-group/docs/DESIGN.md) — RG gear design, auth modes, init sequence
- [AuthZ DESIGN](./DESIGN.md) — Core authorization design
- [RG PRD](../../../gears/system/resource-group/docs/PRD.md) — Product requirements
