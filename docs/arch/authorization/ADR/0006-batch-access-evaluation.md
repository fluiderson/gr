---
status: accepted
date: 2026-11-20
decision-makers: Constructor Fabric Steering Committee
---

# Batch Access Evaluation as an AuthZEN Access Evaluations Operation on the Existing Contract

## Context and Problem Statement

`AuthZResolverApi` exposes one operation, `evaluate`, projected to REST as the internal platform-plane route `POST /authz-resolver/v1/evaluate`. Bulk operations, and gears that compute per-row permitted actions for a response they serve (for example, edit and delete flags for 50 rows of a page), must issue one evaluation per item. The resolver is an internal service; UIs reach it only through such gears. Consumers report latency problems from checking rights one by one, and several gears already fan out single evaluations themselves (quota-enforcement bulk admission, event-broker metadata checks, usage-collector attribution checks, construct profile reads).

The [AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html) defines an Access Evaluations API (§7) for this: an `evaluations` array of independent requests, optional top-level default values, an `options.evaluations_semantic` switch with `execute_all`, `deny_on_first_deny` and `permit_on_first_permit`, positional results and per-item errors carried as `decision: false` with `context.error`. The design must decide how to adopt it within the ToolKit contract, the plugin model, the fail-closed PEP rules and the internal trust model ([#5522](https://github.com/constructorfabric/gears-rust/issues/5522)).

**Key question:** how should a PEP evaluate many independent authorization requests in one call without weakening fail-closed enforcement, tenant/subject isolation or compatibility with the existing single-evaluation route?

## Decision Drivers

* One remote batch invocation must be one HTTP request, not an SDK loop of N requests.
* A batch must produce the same per-item decisions and constraints as independent evaluations of the same inputs.
* No missing, not-evaluated, failed, timed-out or undecodable item may ever be interpreted as an allow; denial and evaluation failure must stay distinguishable.
* The existing `evaluate` operation, its route, its types and their clients must keep working unchanged.
* Work per request and per process must be bounded (bytes, items, concurrency, time) and cancellable.
* Plugins must keep working without changes; native batching must remain possible.
* Alignment with the AuthZEN Access Evaluations API, including default values and evaluation semantics, where it does not conflict with the platform's ToolKit, REST and lint conventions.
* Batch evaluation must not become a substitute for constraint-based LIST authorization.

## Considered Options

* **A.** New `evaluate_batch` operation on `AuthZResolverApi` implementing the AuthZEN Access Evaluations body (default values and all three semantics), batch-only result types with per-item errors, plugin fan-out by default.
* **B.** Option A restricted to complete items and `execute_all`.
* **C.** SDK-side helper that loops over `evaluate`.
* **D.** Separate batch contract (new trait and gear-level projection).
* **E.** Option A served at the AuthZEN default paths (`/access/v1/evaluation`, `/access/v1/evaluations`).

## Decision Outcome

Chosen option: **A**, because it delivers one request per batch, implements the AuthZEN Access Evaluations request model in full, reuses the existing contract, trust model and plugin selection unchanged, and keeps item semantics identical to single evaluation.

The detailed specification is in [DESIGN.md — Batch Evaluation](../DESIGN.md#batch-evaluation-access-evaluations-api). The decisions it records:

1. **Operation and route.** `AuthZResolverApi::evaluate_batch(ctx: PlatformSecurityContext, req: EvaluationBatchRequest) -> Result<EvaluationBatchResponse, CanonicalError>`, projected to `POST /authz-resolver/v1/evaluations`. `POST /authz-resolver/v1/evaluate` is unchanged. The route keeps AuthZEN's resource name under the gear prefix and follows the `/{service}/v{N}/{resource}` form that the DE0801 lint enforces; the REST guideline's `:batch` suffix targets batch writes and would need a lint exception. No `/access/v1/*` routes or aliases are added. The operation is not `#[retryable]`.
2. **Default values.** Top-level `subject`, `action`, `resource` and `context` are defaults for items that omit the same key; a key present in an item replaces the default as a whole (AuthZEN §7.1.1), with no field-level merging. The resolver expands every item into a complete `EvaluationRequest` before a plugin sees it; an item that ends up without one of the four keys fails the whole request with `400`. `context` stays required, as on `/evaluate`. `PolicyEnforcer` compiles each result against its own `require_constraints`, supported properties and negotiated capabilities, so a replaced context cannot widen what the PEP applies. A request without `evaluations`, or with an empty array and top-level defaults, is not treated as a single evaluation; single evaluations use `/evaluate`.
3. **Evaluation semantics.** `execute_all` (default) evaluates every item. `deny_on_first_deny` evaluates in order and stops after the first item that is denied or fails; `permit_on_first_permit` stops after the first item with `decision: true` and no error. A short-circuit response is the evaluated prefix of the items; items after the stopping item have no result and are never an allow. The short-circuit is decided by `decision` and `error` only; the PEP still compiles and applies the constraints of every returned allow.
4. **Result types.** Batch results use new types (`EvaluationBatchResult`, `EvaluationBatchResultContext`, `EvaluationItemError`). `EvaluationResponse` and `EvaluationResponseContext` are not changed, so the single route and the code that builds those types (about 190 struct literals across the repository) are unaffected. `EvaluationBatchResponse::into_results(expected, semantic)` is the fail-closed conversion every SDK consumer uses: it checks that the results form the prefix the semantic allows, marks unevaluated items, and turns any result carrying `error` into an error, whatever its `decision`.
5. **Correlation.** Positional: result `i` answers item `i`; `execute_all` returns one result per item, the short-circuit semantics return a prefix; duplicates are evaluated independently; an empty batch returns an empty result without calling a plugin. The resolver and `into_results` both check the shape.
6. **Errors.** Whole-request failures (decode errors, defaults resolution, limits, plugin discovery, deadline, wrong result shape) are the operation's `CanonicalError`. A plugin error for one item becomes that item's `context.error` (`{status, message}`, AuthZEN §7.2.1) with `decision: false`, classified exactly as the single route classifies the same error (`NoPluginAvailable` and `ServiceUnavailable` → `503`, `Internal` → `500`).
7. **Limits.** The resolver bounds the number of items, the request size, the item evaluations in flight and the time a batch may take. Exceeding the item limit, the size limit or the deadline fails the whole batch (`400`, `413`, `503`); the deadline maps to `503`, matching the PEP's own evaluation deadline, and partial results are not returned. Concurrency bounds only delay evaluations. Limit values, configuration and enforcement belong to the resolver implementation, and the SDK documents the item limit for callers.
8. **Plugin execution.** `AuthZResolverPluginClient::evaluate_batch(requests, semantic, max_concurrency)` with a default implementation that runs `evaluate` per item with bounded, order-preserving concurrency and stops as the semantic requires. Plugins may override it to share work across items only when that work is keyed by every input that affects the result.
9. **SDK and PEP.** The generated REST client sends one request per `evaluate_batch` call and never falls back to single calls. The local client runs the same resolver batch path. `PolicyEnforcer::access_scopes` (`execute_all`) and `PolicyEnforcer::access_scopes_with` (any semantic) evaluate many checks for one `SecurityContext`, send the subject once as a default (and `action` and `context` too when every item has the same value), and validate and compile each returned result exactly as `access_scope_with` does.

### Consequences

* `#[toolkit::contract]` must keep default method bodies (`generate_trait_method` emits only the signature). Without that, adding `evaluate_batch` breaks every `AuthZResolverApi` implementor, almost all of them test doubles. This macro change is a prerequisite of the implementation.
* `OperationBuilder` and `#[toolkit::rest_contract]` need a per-route request body limit to enforce the resolver's request size limit; every route shares the gateway-wide limit (16 MiB default).
* The resolver's configuration gains a `batch` section. Because it uses `deny_unknown_fields`, older configurations stay valid and newer keys are rejected by older resolvers.
* Operators must keep the resolver's batch deadline below the gateway's `request_timeout` and the PEP evaluation deadline; the resolver cannot read the gateway configuration.
* The resolver must be deployed with the batch route before PEPs call it; an older resolver answers `404`, which the SDK surfaces as an evaluation failure.
* Direct callers of `evaluate_batch` that act on `decision` alone must send complete contexts, because an item `context` replaces the default without merging.
* The fallback execution may start up to `max_concurrency - 1` items past a short-circuit stop before cancelling them; evaluation is read-only, so this costs only work.
* The default `evaluate_batch` body for test doubles resolves defaults and honors the semantic, evaluates items sequentially without limits or a deadline, and fails the whole call on the first error. Tests that need per-item errors use doubles that override it.
* The shared AuthZ SDK mock ([#5519](https://github.com/constructorfabric/gears-rust/issues/5519)) must implement `evaluate_batch` with the same resolution, semantics and per-item results.
* PDP-side reuse of shared work (including native batching in `tr-authz-plugin`) and partial results on deadline are separate, additive changes.

### Confirmation

* A REST round-trip test proves that one `evaluate_batch` call issues exactly one HTTP request, including when the server answers with an error.
* Tests compare each batch result with an independent `evaluate` of the same resolved item under the same plugin state, including mixed allow/deny, differing subjects, tenants and token scopes (directly and through overridden defaults), constraints, duplicates and empty batches, for both the in-process and the REST client.
* Tests cover each semantic: the stopping item, the returned prefix, items not evaluated, a stop caused by an item error, and no stop; plus rejection of malformed prefixes by the resolver and by `into_results`.
* Tests cover decode failures (`400`/`422`), defaults resolution failures, the item and body limits, plugin failures (per item and whole batch), the deadline, `decision: true` with `error`, and bounded concurrency, and show that every failure path ends without an allow.
* Code review checks that batch tracing records only counts and never subject identifiers, properties, token scopes or bearer tokens.

## Pros and Cons of the Options

### A. AuthZEN Access Evaluations operation on the existing contract

* Good, because it is one request per batch and one plugin selection per batch.
* Good, because every item is expanded into an ordinary `EvaluationRequest`, so per-item results equal single evaluations by construction when plugins use the default fan-out.
* Good, because default values remove repeated subject and context data from the wire, and the PEP helper sends the subject once.
* Good, because the short-circuit semantics let AND/OR gates stop at the first deciding item instead of evaluating the whole list.
* Good, because it reuses the internal platform-plane route model, OpenAPI generation and the generated REST client.
* Neutral, because it needs the contract macro to keep default method bodies and a per-route body limit.
* Bad, because key-level replacement of defaults can surprise direct callers that expect an item `context` to inherit fields; the PEP helper is not affected.
* Bad, because variable-length responses need shape validation on both the resolver and the client side.

### B. Complete items and `execute_all` only

* Good, because there is no defaults resolution step and every response has one result per item.
* Bad, because shared subject and context data is repeated in every item.
* Bad, because AND/OR gates must evaluate every item, and AuthZEN clients using defaults or short-circuit semantics are rejected.

### C. SDK loop over `evaluate`

* Good, because it needs no contract, resolver or plugin change.
* Bad, because a remote batch costs N HTTP requests, which is the latency problem the issue reports.
* Bad, because every consumer re-implements bounding, ordering and failure handling.

### D. Separate batch contract

* Good, because existing `AuthZResolverApi` implementors are untouched without the macro change.
* Bad, because consumers resolve and wire a second client for the same PDP.
* Bad, because it splits one resolver API across two contracts, two projections and two OpenAPI groups.

### E. AuthZEN default paths

* Good, because AuthZEN-native PEPs could call the resolver without configuring endpoint URLs.
* Bad, because the routes are internal; no external AuthZEN PEP reaches them.
* Bad, because `/access/v1/*` does not fit the gear-prefixed routing of `#[toolkit::rest_contract]`, which has no alias mechanism, and AuthZEN §10.1 already allows non-default endpoint URLs.

## More Information

* [AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html): §7 Access Evaluations API (§7.1.1 Default values, §7.1.2.1 Evaluations semantics, §7.2.1 Errors), §10.1 HTTPS JSON Binding, §11.7 Availability & Denial of Service.
* [Batch & Bulk Operations guideline](../../../../guidelines/DNA/REST/BATCH.md): default limits. The batch evaluation endpoint follows AuthZEN's response shape (positional results, `200` with per-item outcomes) instead of the guideline's `207 Multi-Status` write-batch format, because evaluation is a read with an AuthZEN-defined response.
* [ADR 0001](./0001-pdp-pep-authorization-model.md): PDP/PEP model and AuthZEN choice.
* [#5502](https://github.com/constructorfabric/gears-rust/issues/5502): authorization decision caching, tracked separately.

## Traceability

- **DESIGN**: [DESIGN.md — Batch Evaluation](../DESIGN.md#batch-evaluation-access-evaluations-api)
- **Issue**: [#5522](https://github.com/constructorfabric/gears-rust/issues/5522)
