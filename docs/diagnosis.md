# Graph and risk-first AKS diagnosis

## The organizing model

The new diagnosis engine is independent of the configuration checklist:

1. Validate the approved tenant/subscriptions, targets, collection methods, scenario and assessment selection.
2. Collect permitted evidence. Inventory, IAM and Kubernetes access remain separate collection choices.
3. Build a canonical resource-and-identity graph with evidence references on every relationship.
4. Analyze connected exposures and conditional attack/blast-radius hypotheses.
5. Plan non-mutating and intrusive validation against exact context, namespace, expiry and permission gates.
6. Reconcile selected strategy claims by subject, semantic condition and scope.
7. Derive namespace, resource, cluster and configuration-area reporting views from those reconciled findings.

The [configuration adapter](../src/diagnosis/configuration.mjs) invokes the old evaluator **only when selected**. The [diagnosis engine](../src/diagnosis/engine.mjs) does not call it for graph-only, exposure-only or attack-path-only diagnosis. A graph size failure does not trigger a checklist fallback.

## Two different strategy selections

### Collection methods: what the invoker permits the tool to read

The existing top-level `strategies` field governs collection:

| Method | Permitted scope |
|---|---|
| `azure` | Explicit account/tenant and target ARM metadata |
| `kubernetes` | Scoped workload, service, namespace, RBAC and admission metadata |
| `iam` | Target-scoped assignments, including inherited assignments; no directory enrichment |
| `iam-inventory` | Explicit opt-in to assignment/definition inventory within all approved subscriptions, plus federation metadata for approved observed managed identities |
| `resource-graph` | Explicit opt-in to Azure Resource Graph inventory within all approved subscriptions |
| `dependencies` | Approved explicit and allowlisted linked ARM resources |
| `policy`, `defender`, `advisor` | Their existing metadata collection methods |

**Choosing graph or attack-path analysis never authorizes broader collection.** If `iam-inventory` or `resource-graph` is absent, the corresponding sources are withheld and relationships can remain unresolved. Graph mode does not turn `iam` into subscription-wide inventory.

Resource Graph uses a literal `Resources` query, explicit subscription IDs, bounded pages and continuation-token checks. Only allowlisted resource/identity properties are persisted. Responses outside the subscription allowlist, resource limits and pagination loops are errors. Resource Graph shows the caller's visible resources; it is not proof that every asset in a subscription was visible.

The `resource-graph` Azure CLI extension must be installed by the operator through the approved process. The tool never installs it or enables dynamic installation.

### Assessment strategies: how evidence is analyzed

Use one or more values in `assessment.strategies`:

| Strategy | Result |
|---|---|
| `graph` | Canonical resource/identity inventory, relationships, provenance, conflicts and gaps |
| `exposure` | Connected public entries, API intent conflicts, workload privilege/host sharing and token/grant context |
| `attack-paths` | Conditional workload-to-Kubernetes-secret, federated workload-to-Azure-data, identity-to-Azure-data and AKS admin-credential hypotheses |
| `validation` | Exact-scope interpretation of recorded/live permission, admission and isolated-canary observations |
| `configuration` | Optional existing configuration controls and adherence reports, translated into reconciliation claims where semantics overlap |

Graph construction is a shared foundation, not an implicit request to execute every analysis. `attack-paths` alone can build its required graph without selecting the configuration evaluator. `graph` alone produces no invented vulnerability findings or default low-risk score.

```powershell
# Use the configured selection, or choose a single strategy.
node .\bin\aks-xray.mjs audit --config ".\artifacts\audit-config.json" --assessment-strategies graph

# Combine strategies without the checklist.
node .\bin\aks-xray.mjs audit --config ".\artifacts\audit-config.json" `
  --assessment-strategies graph,exposure,attack-paths

# Include the configuration adapter explicitly.
node .\bin\aks-xray.mjs audit --config ".\artifacts\audit-config.json" `
  --assessment-strategies configuration,exposure,attack-paths
```

If the configuration contains non-passive stages, a selection without `validation` must also explicitly use `--validation-stages passive`. Invalid or contradictory selections are rejected before collection.

## Graph relationships and boundaries

The graph includes:

- Approved ARM resources and shared Azure principals across subscriptions.
- AKS control-plane/kubelet managed-identity references.
- Services selecting pods in the **same namespace**.
- Workloads using service accounts, with effective token-automount configuration.
- Namespace-local Roles/RoleBindings and global ClusterRoles/ClusterRoleBindings.
- Native Kubernetes service-account group relationships. External Entra group membership is **not guessed**.
- Role-definition action/data-action patterns and `notActions`/`notDataActions`.
- Exact workload-identity issuer, subject, audience, client-ID and managed-identity metadata matches.
- Validated current-subject permission observations as separate graph relationships.

Azure IDs are canonicalized case-insensitively. Kubernetes subjects remain cluster-scoped; same-named service accounts in different clusters do not merge. Shared Azure principals merge only within the approved tenant context. Credential values, environment values, arbitrary annotations and condition-expression bodies are not collected.

Role declarations are not effective-access proof. Assignment conditions, deny assignments, PIM, external group membership, network reachability and token exchange can require independent evidence. A vault using access policies blocks the specific Azure-RBAC data-access hypothesis; that does not prove it has no other access path.

Node facts preserve their observations. Contradictory snapshots become explicit conflicting facts rather than a last-write-wins property. Unverified context/ARM binding prevents Kubernetes graph joins. Intentional Azure-only collection is labelled ARM-only, not cross-plane verified.

## Evidence tiers

| Tier | Meaning |
|---|---|
| `configured-exposure` | A configuration or relationship supports a potential exposure; exploitation was not established |
| `plausible-exploitability` | A connected hypothesis has its modeled prerequisites satisfied or explicitly assumed; it remains conditional, not proof of compromise |
| `validated-behavior` | A supported recorded method establishes the exact stated condition for its subject, target/context, namespace and timestamp |

Initial compromise is never inferred from a public service. To model a compromised foothold, supply exact graph node IDs in `scenario.assumedCompromise`. These are **assumptions**, not test results. The report retains them in each path's prerequisite list and caps confidence.

Examples of deliberately different assertions:

- A current assessor's successful self-subject review does not validate a workload service account's permissions.
- Denying a new privileged Pod does not prove existing privileged Pods were removed.
- A successful owned canary HTTP request does not validate production ingress, application authentication or an entire attack path.
- A title or `validated-behavior` label without a valid method/receipt cannot promote a finding.

## Permission-aware stages

`assessment.stages` defaults to `["passive"]`. Neither read-only approval nor selecting `validation` authorizes resource changes.

### Non-mutating

Select `non-mutating` and provide `assessment.approvals.nonMutating`:

```json
{
  "approved": true,
  "contexts": ["<exact-existing-context>"],
  "namespaces": ["<approved-namespace>"],
  "tests": ["authorization-review", "admission-dry-run"],
  "expiresAt": "<ISO-8601-owner-approved-expiry>"
}
```

- `authorization-review` uses `kubectl auth whoami` and fixed SelfSubjectAccessReview requests for secret-list, pod-create and pod-exec authorization. It never lists secret content, impersonates another identity or executes a workload.
- Identity is checked before and after review. A changed actor invalidates the receipt.
- `admission-dry-run` first reviews Pod-create permission, then submits a fixed privileged negative Pod using server-side dry-run. Only a specific restricted-PSA rejection or observed privilege-removing mutation can establish the corresponding negative result. Unrelated Forbidden/timeout errors are not successful policy enforcement.
- Missing API support or review permission is an explicit gap. There is no fallback to admin credentials.

### Separately approved intrusive canaries

Additionally select `intrusive`, approve `assessment.approvals.intrusive`, and include `intrusive-preflight` in the approved non-mutating tests:

```json
{
  "approved": true,
  "contexts": ["<exact-existing-context>"],
  "suites": ["security", "connectivity"],
  "expiresAt": "<ISO-8601-owner-approved-expiry>",
  "limits": {
    "requests": 40,
    "concurrency": 2,
    "durationSeconds": 10,
    "latencyBudgetMs": 2000,
    "errorBudgetPercent": 0
  }
}
```

Preflight reviews the permissions for the **exact future owned namespace**, including creation, observation, cleanup and the selected exec/port-forward path. Unknown/denied permissions block mutation. Approval alone is not a grant.

The runner uses the prepared UUID when creating that namespace, rechecks identity/context and expiry, and retains the existing hard caps: 200 requests, four workers, 30 seconds, pacing, four-minute Job deadlines and UID/ownership-checked cleanup. Resource types and namespace are fixed; arbitrary manifests, existing-workload exec, credential harvesting, node drains and destructive exploits are not supported.

Expiry is enforced during execution, not just at its start. It stops new test activity and cancels bounded work. **Owned cleanup remains permitted after expiry** to avoid leaving test resources. A measurement, cancellation, identity or cleanup failure stops subsequent intrusive activity and remains an explicit report error.

The standalone legacy `active` command remains a direct compatibility runner with its documented explicit-authorization contract. Use the strategy-enabled `audit` workflow for expiring approvals and permission-matrix orchestration; neither is run implicitly by collection or report rendering.

## Reconciliation, risk and confidence

Claims merge only when subject, semantic condition and scope match. Contributions from every selected strategy are retained. Contradictory support/refutation becomes `conflicting`, not a confidence vote or last-write-wins result. Observed configuration, possible paths and test receipts remain inspectable separately.

Risk is a **project-defined review-priority index**, not CVSS or attack probability:

- Consequence is adjusted by explicit business criticality and data sensitivity.
- Rule-specific feasibility and intended public/private application exposure influence priority.
- Priority is `round(adjusted impact * feasibility index / 100)`, bounded to 1-100.
- Confidence is independent. Low confidence does not numerically discount the risk.
- Unsupported/refuted/inconclusive risk is `null`, never a default healthy zero.
- Missing observations, partial sources, stale data, unverified binding, scenario assumptions and conflicts limit confidence.

Namespace and configuration-area views use the same finding IDs and highest risk. They do not reevaluate or average away the underlying findings. Optional legacy adherence scores are explicitly **higher-is-better**, unlike risk.

## Portable offline reassessment

Strategy-enabled audits produce:

| Artifact | Purpose |
|---|---|
| `diagnosis.json` | Unified graph/risk findings, contributions, confidence, receipts and reporting views |
| `graph.json` | Complete canonical node/edge/provenance model |
| `assessment-plan.json` | Permission-aware stage/action state |
| `validation-records.json` | Scoped observations, denials, errors and cleanup evidence |
| `diagnosis-evidence.json` | Portable references to hashed per-target evidence plus scenario/options/receipts |
| `diagnosis.md`, `report.html` | Diagnosis-first human reports and interactive graph explorer |
| `cluster-NNN/evidence.json` | Collected projected target evidence |
| `cluster-NNN/configuration/` | Optional classic report, only when `configuration` was selected |

```powershell
# Reconcile a different single strategy without contacting Azure or Kubernetes.
node .\bin\aks-xray.mjs diagnose --input ".\artifacts\my-audit\diagnosis-evidence.json" `
  --assessment-strategies exposure --output ".\artifacts\exposure-only"

# Or combine multiple analyses over the same immutable collected evidence.
node .\bin\aks-xray.mjs diagnose --input ".\artifacts\my-audit" `
  --assessment-strategies configuration,exposure,attack-paths --output ".\artifacts\combined"

node .\bin\aks-xray.mjs report --input ".\artifacts\combined\diagnosis.json"
node .\bin\aks-xray.mjs verify --input ".\artifacts\combined"
```

`diagnose` is always offline and schedules no fresh non-mutating or intrusive execution. Saved receipts retain their original scope/time and must still satisfy age/method checks. Choosing an additional strategy cannot recreate data that was not collected; gaps remain explicit.

Bundle references are restricted to dataset-contained paths and SHA-256 checked before parsing. Traversal, absolute paths, symlink escapes and altered hashes are rejected. Hashes detect edits, not collector authorship. JSON input/output and total loaded evidence are bounded to 100 MiB; split larger scopes. Graph/path/inventory/check limits are explicit options, and limit failures are not success-shaped truncation.

The HTML graph list/neighborhood display is bounded for browser responsiveness and discloses the shown/total counts. Searches operate over the full model, and JSON exports retain all nodes/relationships. Browser strategy filters are views, not execution controls or new reconciliations.

Protect every artifact: identity names, grants, topology and endpoints are sensitive even without credentials. Imported JSON is not a general secret-redaction service. No real assessment outputs should be committed or published.

## Offline demonstration and limits

```powershell
node .\bin\aks-xray.mjs demo --assessment-strategies graph,exposure,attack-paths,validation,configuration
```

This generates clearly labelled synthetic observations, assumed footholds and simulated receipts to illustrate all tiers without any cloud connection.

Implemented hypotheses are bounded pattern families, not an exhaustive exploit catalogue. Effective network policy/routing, external Entra group membership, deny/PIM evaluation, image CVEs/signatures, runtime escape proof, application semantics, backup recovery and workload-specific production tests remain independent evidence. The new engine does not equate a graph, a high-confidence configuration observation or an empty findings list with a secure workload.
