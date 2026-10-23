# AKS X-Ray

Diagnose Azure Kubernetes Service and AKS enabled by Azure Arc using resource/identity graphs, connected exposure analysis, conditional attack paths, permission-aware validation and strategy reconciliation.

The CLI reads evidence for **explicit, authorized Azure targets and Kubernetes contexts**. The graph/risk-first engine lets the invoker conduct an assessment using a **single strategy or multiple reconciled strategies**. Configuration and namespace summaries are reporting views, not the organizing principle.

The optional configuration adapter retains **92 controls across 16 categories** and **29 Microsoft Learn references** reviewed on **2026-10-22**. It is not invoked by graph-only, exposure-only or attack-path-only diagnosis. Its results distinguish:

- Observed adherence to a specific recommendation.
- Observed deviations and misconfiguration.
- Configuration conflicts and missing declarations.
- Evidence gaps, collection errors and controls that need human/operational review.

Complete configuration assertions receive **project-defined 1-100 scores**, with configuration-area, five-pillar Azure Well-Architected Framework and independently evaluated namespace summaries. Missing, partial, unverified and manual evidence stays **unscored**, never an invented healthy rating.

Outputs describe configuration observed during collection and any synthetic test results. They are not a Microsoft product, official Microsoft score, compliance certification, exhaustive vulnerability scan, or conclusion that a cluster is healthy. Manual controls identify checks that static inventory cannot complete. Active suites test generated resources within fixed limits; they do not replace workload-specific performance testing or an authorized penetration test.

## Choose an assessment strategy

The [audit template](examples/audit-config.json) now selects the new engine:

```json
"assessment": {
  "strategies": ["graph", "exposure", "attack-paths"],
  "stages": ["passive"]
}
```

| Strategy | Primary purpose |
|---|---|
| `graph` | Approved resources, shared identities, workload/identity/RBAC relationships, provenance and unresolved links |
| `exposure` | Connected public/API exposure and workload privilege/token/grant context |
| `attack-paths` | Conditional paths and explicit satisfied/assumed/unknown/blocked prerequisites |
| `validation` | Exact-scope permission, admission and owned-canary observations |
| `configuration` | Optional classic controls and adherence reporting |

```powershell
node .\bin\aks-xray.mjs audit --config ".\artifacts\audit-config.json" --dry-run
node .\bin\aks-xray.mjs audit --config ".\artifacts\audit-config.json" --assessment-strategies exposure
node .\bin\aks-xray.mjs audit --config ".\artifacts\audit-config.json" --assessment-strategies graph,exposure,attack-paths,configuration

# Reconcile saved evidence using a different selection, with no cloud access.
node .\bin\aks-xray.mjs diagnose --input ".\artifacts\my-audit\diagnosis-evidence.json" `
  --assessment-strategies exposure,attack-paths

# Generate a graph/risk-first synthetic report without any live commands.
node .\bin\aks-xray.mjs demo --assessment-strategies graph,exposure,attack-paths,validation,configuration
```

The new report distinguishes **configured exposure**, **plausible exploitability** and **validated behavior**. It preserves each strategy's contribution and conflicting evidence. Risk is **higher-is-worse** review priority, confidence is separate, and unknown risk stays unscored.

Top-level collection `strategies` still govern what may be read. Selecting an analysis never grants broader access: subscription-wide `resource-graph` and `iam-inventory` are separate opt-ins. Non-mutating and intrusive stages have separate expiring approvals; an intrusive approval is insufficient without a fresh exact-scope permission preflight. Default templates authorize no validation.

See [the complete diagnosis model, stage approvals, output format and limits](docs/diagnosis.md).

## HTML reports and website

**Website:** [chadhage.github.io/aks-x-ray](https://chadhage.github.io/aks-x-ray/).

Open [site/index.html](site/index.html) directly in a browser. It starts with prerequisites, local setup, a read-only collection command builder, and instructions for opening your results. No assessment is loaded by default. Choose **View a sample assessment (synthetic)** to open the separate [sample report](site/sample.html), or **Open assessment JSON** to view your own collected results locally. The assessment-control catalogue, filters, methodology, and Microsoft Learn references remain available without loading a report.

The [Pages workflow](.github/workflows/pages.yml) validates and rebuilds the site on pushes to `master` or manual dispatch. It publishes **only the generated getting-started homepage and synthetic sample HTML**, not repository contents or collected assessment artifacts. Never publish real cluster reports to this public site. Opening a local assessment through the website reads it in your browser without uploading it. Generated run reports open directly to their assessment results.

To generate example reports without connecting to Azure:

```powershell
git clone https://github.com/chadhage/aks-x-ray.git
Set-Location aks-x-ray
npm run demo
```

The command prints a unique output directory. Open its `report.html`.

## Prerequisites

| Operation | Requirements |
|---|---|
| View a report | Current JavaScript-enabled browser; reports are self-contained |
| Demo / offline assessment / report generation | Node.js 22+; no npm dependencies |
| Read-only collection | Node.js 22+, Azure CLI, approved Azure metadata permissions and existing kubeconfig contexts; compatible `kubectl` and `kubelogin` when the Kubernetes strategy needs them |
| Azure Local metadata | Current `az aksarc` extension, installed **by you** before collection; the current command reference requires Azure CLI 2.77+ |
| Active synthetic tests | Additional explicitly approved write/exec/port-forward permissions, schedulable Linux **amd64** capacity and access to the official MCR image |

Only the explicit `login` command signs you in, using Azure CLI device-code authentication. It does not capture device codes or tokens in artifacts. Azure CLI manages its own local credential cache. No collection command signs in implicitly, invokes `get-credentials`, installs extensions or changes Kubernetes context; every Azure read specifies its subscription. A subscription GUID is a scope identifier, not a credential; supply it locally rather than posting it publicly.

```powershell
node .\bin\aks-xray.mjs doctor --platform cloud
node .\bin\aks-xray.mjs catalog
```

## Parameterized Blue Team audit

There are no embedded customer tenant IDs, subscription IDs, target names or approval decisions. The invoker supplies **tenant and subscription GUIDs as runtime parameters**: either in a local copy of [the audit configuration](examples/audit-config.json), and/or as `--tenant` / `--subscriptions` overlays on `login`, `discover` and `audit`. They are never inferred from the Azure CLI default account or an Azure MCP default subscription. Documented by [the JSON schema](schemas/audit-config.schema.json). Unknown fields, duplicate targets, invalid IDs, scope expansion and missing approval are rejected before collection.

Both identity planes are supported; the invoker chooses at runtime:

| Identity plane | How the invoker authenticates | What collects |
|---|---|---|
| Azure CLI device code | `login --tenant <guid> --subscriptions <guid,guid>` in the invoker's terminal | This CLI (`az` read-only commands) |
| Azure MCP signed-in identity | Existing Copilot/Azure MCP session | Agent tools using the same invoker-supplied GUIDs |

All three `targetSelection` modes are supported: `named`, `default-subscription-only`, and `all-accessible-clusters`.

1. Copy the template to a protected, ignored local location. Replace **every placeholder**, select the allowed strategies, provide the intended scenario and choose `targetSelection`: `named` (explicit `targets`), `default-subscription-only` (exactly one subscription GUID; clusters are discovered at collection time) or `all-accessible-clusters` (every AKS cluster in the authorized subscriptions). Named selection requires target clusters/contexts. Discovery modes may omit `targets` for ARM-only collection; the `kubernetes` strategy still needs explicit per-cluster context mappings. Remove unused subscription IDs and add explicitly approved dependency resource IDs.
2. Obtain resource-owner approval. Only then set `authorization.readOnly` to the boolean `true`; the shipped template deliberately has it set to `false`. This is an invoker assertion, not an access grant.
3. Sign in explicitly, discover approved targets if needed, review the offline plan, then collect:

```powershell
Copy-Item .\examples\audit-config.json .\artifacts\audit-config.json
# Edit the copied file locally before continuing.
$configPath = ".\artifacts\audit-config.json"
$config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
$subscriptions = $config.subscriptions -join ','

node .\bin\aks-xray.mjs login --tenant $config.tenant --subscriptions $subscriptions
node .\bin\aks-xray.mjs discover --tenant $config.tenant --subscriptions $subscriptions --authorize-readonly
node .\bin\aks-xray.mjs audit --config $configPath --dry-run
node .\bin\aks-xray.mjs audit --config $configPath --output ".\artifacts\approved-audit" --fail-on high

# Overlay tenant, subscriptions and target selection at runtime instead of editing the file:
node .\bin\aks-xray.mjs audit --config $configPath --tenant $env:AKS_XRAY_TENANT `
  --subscriptions $env:AKS_XRAY_SUBSCRIPTIONS --target-selection all-accessible-clusters --dry-run
```

Bash, PowerShell and the direct Node launcher all accept the same commands. For example, after editing a local config:

```bash
bash scripts/aks-xray.sh login --tenant "$TENANT_ID" --subscriptions "$SUBSCRIPTION_IDS"
bash scripts/aks-xray.sh audit --config "$AUDIT_CONFIG" --dry-run
bash scripts/aks-xray.sh audit --config "$AUDIT_CONFIG" --output "$AUDIT_OUTPUT"
```

`SUBSCRIPTION_IDS` is comma-separated. IDs, contexts and approval values are never inferred from a default account. Device authentication waits at most ten minutes and uses the caller's terminal; a Conditional Access rejection is an error, not permission to bypass policy. All listed subscriptions must have enabled CLI account metadata for the requested tenant. Use separate audit configurations for separate tenants.

### Invoker-selected strategies

| Strategy | Authorized collection |
|---|---|
| `azure` | Required tenant/subscription verification, exact ARM target identity, node pools, diagnostics and maintenance dependencies |
| `kubernetes` | Scoped get/list inventory, workloads, namespace policy labels, Roles/RoleBindings/ClusterRoles, bindings and admission-webhook declarations |
| `iam` | Azure role assignments at the target scope, including inherited grants; no directory-name enrichment or identity impersonation |
| `iam-inventory` | Explicit subscription-wide assignment/definition inventory and approved observed managed-identity federation metadata |
| `resource-graph` | Explicit subscription-scoped resource/identity inventory with bounded pagination; preinstalled CLI extension required |
| `policy` | Existing target Azure Policy states; no scan trigger or assignment changes |
| `defender` | Containers plan metadata and existing assessment states; no new image scan or sensor installation |
| `advisor` | Existing recommendation metadata filtered to the target and approved dependency IDs; no refresh |
| `dependencies` | Approved resource IDs and allowlisted cluster/subnet references, within the explicit subscription allowlist |

Removing a strategy prevents its commands from running. Dependent assertions become `notRun` evidence gaps, not passes. Without `kubernetes`, the report clearly identifies an **ARM-only binding** and does not claim cross-plane correlation or namespace coverage. Category selection still determines assessed controls; explicitly selected audit strategies can collect their supplemental metadata even when a category does not use it. Legacy single-target `collect` remains available below.

Dependency traversal recognizes cluster subnet, disk-encryption, monitoring-workspace and outbound-IP references, then allowlisted subnet NSG/route/NAT references. It also reads the explicit `relatedResourceIds` supplied by the invoker. It is **not** a complete application dependency discoverer. Registry, vault, storage, subnet, NSG, route, public-IP, workspace and disk-encryption metadata has field allowlists; unsupported types retain identity metadata and require review. Secrets, account keys, registry passwords and arbitrary resource properties are not exported.

`maxRelatedResources` defaults to 200 and can be set to 1-1000. An out-of-scope reference, limit, denied resource or malformed response is an explicit error; successful partial metadata is retained, but dependent controls cannot claim complete evidence. No subscription is added automatically.

### Scenario and multi-target output

`scenario.name` and `scenario.profile` are required for audits. Optional fields are:

| Field | Meaning / default |
|---|---|
| `apiAccess` | `private`, `restricted-public`, or `either` (default); compares API configuration, not live reachability |
| `minimumReplicas` | 1-100; defaults to 2 in production, 1 in development |
| `minimumZones` | 1-3 declared cloud zones; defaults to 2 in production, 1 in development |
| `allowedRegistries` | Explicit lowercase registry hosts; an empty/omitted list leaves registry approval unassessed |

Use `namespaces` for an explicit namespace allowlist, or `null`/omission for all reachable non-system namespaces. `includeSystem` is an explicit boolean. These fields and authorization are parameters, not approval prompts silently answered by the tool.

With `assessment`, the audit writes a diagnosis-first report, graph, action plan, validation ledger and portable evidence dataset. Per-target raw evidence is retained; classic reports are created only for the selected configuration adapter. See [diagnosis artifacts](docs/diagnosis.md#portable-offline-reassessment).

For compatibility, configurations **without** `assessment` retain the classic `audit.json`/`audit.md` index and per-cluster configuration reports. Existing `collect`, `assess`, `active` and classic `report` commands remain supported. One target's API errors do not erase other targets' reports. The audit exits with the highest-priority outcome: evidence/operational errors (2), severity gate failures (1), then completion (0).

Verify the root index and each cluster directory separately; root verification does not recursively authenticate child evidence. Protect config files and all outputs. Never submit them to a public repository or website.

For diagnosis outputs, `--fail-on` gates the project-defined review-priority score (`high` 70+, `medium` 40+, `low` 15+, `info` 1+), not CVSS. Requested blocked/error validation, invalid binding, missing required data and graph/path limits take precedence with exit code 2. Intentionally withheld collection methods remain explicit gaps rather than grants or healthy conclusions.

## Assess a cloud AKS cluster

First establish your Azure login, permissions and Kubernetes context using your organization's normal process. Then:

```powershell
.\scripts\Invoke-AksXRay.ps1 collect `
  --platform cloud `
  --context "my-aks-context" `
  --subscription "<subscription-guid>" `
  --resource-group "my-resource-group" `
  --cluster "my-aks-cluster"
```

Bash / macOS / Linux:

```bash
bash scripts/aks-xray.sh collect \
  --platform cloud \
  --context "my-aks-context" \
  --subscription "<subscription-guid>" \
  --resource-group "my-resource-group" \
  --cluster "my-aks-cluster"
```

### Select categories or namespaces

```powershell
node .\bin\aks-xray.mjs collect `
  --platform cloud --context "my-aks-context" `
  --subscription "<subscription-guid>" --resource-group "my-resource-group" --cluster "my-aks-cluster" `
  --categories networking,storage --namespaces payments,orders `
  --output ".\artifacts\network-and-storage"
```

Omit `--categories`, or use `--categories all`, to select all categories. Only dependencies of applicable selected controls are collected, plus target-binding metadata. `--namespaces` makes namespaced API requests individually instead of collecting all namespaces.

Production is the default recommendation profile. Use `--profile development` to explicitly exclude production-only tier/redundancy recommendations. Workload checks exclude `kube-system`, `kube-public` and `kube-node-lease` by default. Use `--include-system` to inspect those workloads too; privileged platform components may then produce intentional exceptions, not automatic evidence of a defect.

### Azure Local

Use the same CLI with `--platform local` and the target's existing context:

```powershell
node .\bin\aks-xray.mjs collect `
  --platform local --context "my-local-aks-context" `
  --subscription "<subscription-guid>" --resource-group "my-local-resource-group" --cluster "my-local-cluster"
```

The Local adapter uses `az aksarc show`; cloud-only properties are **not** assumed. Local control-plane count and endpoint binding use the documented `controlPlane` API fields. Physical hosts, Arc health, certified hardware, storage resilience and disconnected-operation dependencies require separate evidence. There are no dedicated adapters for legacy AKS on Windows Server/old HCI APIs, arbitrary Arc-connected Kubernetes or AKS on bare metal. See [platform coverage](docs/coverage.md).

## What is produced

Each run writes to a new directory under ignored [artifacts/](artifacts/), or an **empty** directory you supply.

| File | Purpose |
|---|---|
| `report.html` | Self-contained HTML report with finding filters, observed values, scope and source references |
| `evidence.json` | Versioned, projected inventory, commands, collection timestamps and explicit errors |
| `assessment.json` | Machine-readable findings, 1-100/null scores, WAF/area/namespace ratings, namespace-specific results, observations, provenance and scope |
| `assessment.md` | Markdown report grouped by area, WAF pillar and namespace |
| `checksums.json` | SHA-256 hashes for the other generated files; detects edits, not authorship |
| `active-manifest.json` | Active runs only: exact synthetic workload resources |

Reports have no analytics, external assets, backend or browser-to-cluster connection. The website can open an `assessment.json` locally. Use the CLI to evaluate raw evidence; the browser displays assessment results.

**Protect all outputs.** Metadata is still sensitive: resource names, labels, endpoints, RBAC subjects and subscription identifiers can reveal architecture. Output folders are ignored by Git; POSIX files use private modes, while Windows relies on inherited ACLs. Use a protected local directory and review before sharing. Arbitrary imported JSON is not a secret-redaction service.

## Offline reassessment and integrity

```powershell
node .\bin\aks-xray.mjs assess --input ".\artifacts\my-run\evidence.json" --categories security
node .\bin\aks-xray.mjs report --input ".\artifacts\my-run\assessment.json"
node .\bin\aks-xray.mjs verify --input ".\artifacts\my-run"
```

Use the matching catalogue version **and digest**. Catalogue text is included in the digest, so wording-only revisions also require the matching repository revision. Reassessment cannot evaluate evidence that was not collected. The source catalogue and all control assertions remain in the repository for reproducibility. Collection spans multiple API requests and is not an atomic snapshot.

## Active tests require authorization

**Do not start here on a production cluster.** Read the [active-testing runbook](docs/active-testing.md), approve scope and permissions, and validate the runner on an expendable nonproduction cluster first. No live-cluster validation has been performed as part of this repository's initial implementation.

```powershell
node .\bin\aks-xray.mjs active `
  --input ".\artifacts\my-run\evidence.json" `
  --suite all `
  --authorize-active `
  --confirm-context "my-aks-context"
```

| Suite | Actual measurement |
|---|---|
| `connectivity` | DNS resolution and HTTP from a synthetic probe pod to its synthetic ClusterIP service |
| `end-to-end` | Three expected-marker requests over loopback-only `kubectl port-forward` |
| `load` | Bounded HTTP smoke measurements; actual error percentage and nearest-rank p95 |
| `security` | A privileged pod is denied by restricted PSA on a **server-side dry-run**, without being created |

Hard caps are **200 requests, 4 workers, 30 seconds and 100 ms worker pacing**. Defaults are 40 requests, 2 workers, 10 seconds, zero tolerated errors and a 2,000 ms p95 budget. Budgets are **operator-defined smoke thresholds, not Microsoft SLOs**. Tests target only the isolated synthetic service, never an arbitrary URL.

The runner creates an unpredictable owned namespace, constrained jobs with four-minute deadlines, resource quota and network policies. Cleanup checks ownership labels and UID before deleting that exact namespace. Cleanup failure is prominent and returns exit code 2. Neither `audit` nor `collect`, even with all strategies/categories, **ever executes these tests**. ARM-only evidence is insufficient; tenant-bound active runs recheck account scope before any Kubernetes command.

## Coverage

| Category ID | Assessment focus |
|---|---|
| `control-plane` | Target binding, API exposure, production tier |
| `identity` | RBAC, managed Entra, local accounts, workload identity, privileged bindings |
| `nodes` | Ready/pressure conditions, system capacity, isolation, hardware/OS review |
| `networking` | Policies, ingress TLS declarations, EndpointSlices, IPv4/IPv6 conflicts, egress/DNS review |
| `security` | Privilege, HostProcess, Linux contexts, host sharing/mounts, image references, Defender |
| `workloads` | Requests/limits, quantity conflicts, probes, rollout/pod health, HPA bounds |
| `reliability` | Replicas, PDB selector coverage/drain blockers, topology, cloud zones |
| `storage` | PVC binding, Azure Disk topology, backend/retention/encryption review |
| `observability` | Audit routing, managed metrics/logs, warning reasons, alerts and SLO proof |
| `governance` | Policy enablement, quotas, admission/defaults/compliance review |
| `cost` | Autoscaling bounds, NAP configuration, measured resource use and capacity costs |
| `lifecycle` | Upgrade/OS channels, maintenance windows, current support-window review |
| `business-continuity` | Restore evidence, RPO/RTO, region/site recovery |
| `azure-local` | Provisioning, control-plane redundancy, host/Arc/physical infrastructure evidence |
| `active-validation` | Authorized isolated connectivity, HTTP, load-smoke and admission tests |
| `dependencies` | Approved ACR/vault/storage/subnet/NSG settings and explicit dependency-completeness review |

See the [complete machine-readable catalogue](catalog/controls.json), [Microsoft source registry](catalog/sources.json), [methodology](docs/methodology.md), [permissions](docs/permissions.md) and [coverage boundaries](docs/coverage.md).

## Interpreting results and exit codes

Pass means the **specific assertion** has supporting evidence. It never means that a whole architectural category, application or cluster is certified. Context-dependent recommendations need exception review. Missing permissions/API fields are `unknown`, not successful empty lists; manual controls are always `review`; unauthorized collection strategies and active suites are `notRun`.

- **0**: assessment/report completed; no requested severity gate failed. Reviews/not-run tests can remain.
- **1**: a failure meets `--fail-on high|medium|low|info`. Severity gating is opt-in; default is `none`.
- **2**: invalid input, unavailable/partial evidence, evaluation error, unverified/mismatched target, or active cleanup failure.

Evidence gaps take precedence over a severity gate. Alignment is `pass / (pass + fail)` only with verified target binding; evidence coverage separately includes reviews and not-run tests in its denominator. Do not turn either number into an overall health/compliance score.

The separate **1-100 configuration rubric** uses `round(1 + 99 * adherence fraction)` for complete multi-resource assertions, 100 for scalar passes and 1 for scalar failures. Incomplete or unverified findings have `score: null`. Group scores are severity-weighted means (high 5, medium 3, low/info 1), with separate coverage denominators that retain all applicable unscored controls. A high scored-subset rating can coexist with serious failures and large evidence gaps. Read [the exact methodology](docs/methodology.md), not just the number.

## Development and validation

```powershell
npm run check
npm test
npm run build:site
node --test --experimental-test-coverage
az bicep build --file .\infra\metadata-reader.bicep --stdout
```

There are no runtime or npm development dependencies. Tests use Node's built-in runner, synthetic Azure/Kubernetes responses, a local loopback HTTP server and mocked mutation/cleanup paths. They do not contact Azure or Kubernetes. New behavior follows red/green TDD, including explicit negative tests for tenant mismatches, missing consent, strategy exclusions, dependency limits, partial settings, forged ratings and active-test boundaries. Repeat passing suites to check repeatability; a finite test run does not prove that flakiness is impossible. The [CI workflow](.github/workflows/validate.yml) covers Node 22/24 on Windows/Linux without Azure credentials.

The native-launcher regression uses PowerShell 7 (`pwsh`) on Windows and Bash on Linux/macOS. Respect your organization's script-execution policy; if a launcher is blocked, use the direct Node CLI instead of changing or bypassing policy.

The optional [cloud metadata Reader Bicep](infra/metadata-reader.bicep) and [Kubernetes read-only role](manifests/reader-clusterrole.yaml) are **not deployed automatically**. The YAML role uses YAML 1.2's JSON syntax so its complete contents and permissions can be validated without a YAML package. Permission grants must be approved separately.

Before changing controls, read [contribution guidance](CONTRIBUTING.md). Missing evidence and checks that were not run remain visible in the results.
