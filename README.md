# AKS X-Ray

Configuration and evidence assessment for Azure Kubernetes Service and AKS enabled by Azure Arc on Azure Local.

The toolkit compares observed configuration with selected Microsoft guidance for an **explicit Azure target and Kubernetes context**, then produces a standalone microsite and machine-readable evidence.

The initial catalogue contains **71 controls across 15 architectural categories**, grounded in **20 official Microsoft Learn references** reviewed on **2026-10-20**. It distinguishes:

- Observed adherence to a specific recommendation.
- Observed deviations and misconfiguration.
- Configuration conflicts and missing declarations.
- Evidence gaps, collection errors and controls that need human/operational review.

Outputs are point-in-time engineering evidence, not a Microsoft product, compliance certification, exhaustive vulnerability scan, or conclusion that a cluster is healthy. Manual assessments identify where static inventory is insufficient. Active suites provide bounded synthetic validation; they are not a replacement for workload-specific performance testing or an authorized penetration test.

## Microsite

**Published microsite:** [chadhage.github.io/aks-x-ray](https://chadhage.github.io/aks-x-ray/).

Open [site/index.html](site/index.html) directly in a browser. It includes a labelled synthetic report, the assessment-control catalogue, category and platform filters, a command builder, methodology, and Microsoft Learn references.

The [Pages workflow](.github/workflows/pages.yml) validates and rebuilds the site on pushes to `master` or manual dispatch. It publishes **only the generated synthetic standalone HTML**, not repository contents or collected assessment artifacts. Never publish real cluster reports to this public site. Opening a local assessment through the microsite reads it in your browser without uploading it.

To generate your own synthetic artifacts without touching Azure:

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
| Read-only collection | Node.js 22+, Azure CLI, compatible `kubectl`, your existing Azure sign-in and kubeconfig context; `kubelogin` if your context needs it |
| Azure Local metadata | Current `az aksarc` extension, installed **by you** before collection; the current command reference requires Azure CLI 2.77+ |
| Active synthetic tests | Additional explicitly approved write/exec/port-forward permissions, schedulable Linux **amd64** capacity and access to the official MCR image |

The tool never signs you in, requests credentials, invokes `get-credentials`, installs an extension, switches context or chooses a subscription implicitly. A subscription GUID is a scope identifier, not a credential; supply it locally rather than posting it publicly.

```powershell
node .\bin\aks-xray.mjs doctor --platform cloud
node .\bin\aks-xray.mjs catalog
```

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

### Isolate categories or namespaces

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

The Local adapter uses `az aksarc show`; cloud-only properties are **not** assumed. Local control-plane count and endpoint binding use the documented `controlPlane` API fields. Physical hosts, Arc health, certified hardware, storage resilience and disconnected-operation dependencies require separate evidence. Legacy AKS on Windows Server/old HCI APIs, arbitrary Arc-connected Kubernetes and AKS on bare metal are not automatically certified as supported adapters. See [platform coverage](docs/coverage.md).

## What is produced

Each run writes to a new directory under ignored [artifacts/](artifacts/), or an **empty** directory you supply.

| File | Purpose |
|---|---|
| `report.html` | Standalone themed microsite; search/filter findings, evidence, scope and official citations |
| `evidence.json` | Versioned, projected inventory, commands, collection timestamps and explicit errors |
| `assessment.json` | Machine-readable findings, observations, provenance, scope and summary |
| `assessment.md` | Portable human-readable summary |
| `checksums.json` | SHA-256 hashes for the other generated files; detects edits, not authorship |
| `active-manifest.json` | Active runs only: exact synthetic workload resources |

Reports have no analytics, external assets, backend or browser-to-cluster connection. The microsite can open an `assessment.json` locally; raw evidence is evaluated by the CLI, not arbitrary browser code.

**Protect all outputs.** Metadata is still sensitive: resource names, labels, endpoints, RBAC subjects and subscription identifiers can reveal architecture. Output folders are ignored by Git; POSIX files use private modes, while Windows relies on inherited ACLs. Use a protected local directory and review before sharing. Arbitrary imported JSON is not a secret-redaction service.

## Offline reassessment and integrity

```powershell
node .\bin\aks-xray.mjs assess --input ".\artifacts\my-run\evidence.json" --categories security
node .\bin\aks-xray.mjs report --input ".\artifacts\my-run\assessment.json"
node .\bin\aks-xray.mjs verify --input ".\artifacts\my-run"
```

Use the matching catalogue version **and digest**. Reassessment cannot invent uncollected evidence. The source catalogue and all control assertions remain in the repository for reproducibility. Collection spans multiple API requests and is not an atomic snapshot.

## Explicitly authorized active validation

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

The runner creates an unpredictable owned namespace, constrained jobs with four-minute deadlines, resource quota and network policies. Cleanup checks ownership labels and UID before deleting that exact namespace. Cleanup failure is prominent and returns exit code 2. `collect`, even with all categories, **never executes these tests**.

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
| `cost` | Autoscaling bounds, NAP capability, measured rightsizing/capacity review |
| `lifecycle` | Upgrade/OS channels, maintenance windows, current support-window review |
| `business-continuity` | Restore evidence, RPO/RTO, region/site recovery |
| `azure-local` | Provisioning, control-plane redundancy, host/Arc/physical infrastructure evidence |
| `active-validation` | Authorized isolated connectivity, HTTP, load-smoke and admission tests |

See the [complete machine-readable catalogue](catalog/controls.json), [Microsoft source registry](catalog/sources.json), [methodology](docs/methodology.md), [permissions](docs/permissions.md) and [coverage boundaries](docs/coverage.md).

## Interpreting results and exit codes

Pass means the **specific assertion** has supporting evidence. It never means that a whole architectural category, application or cluster is certified. Context-dependent recommendations need exception review. Missing permissions/API fields are `unknown`, not successful empty lists; manual controls are always `review`; unauthorized active suites are `notRun`.

- **0**: assessment/report completed; no requested severity gate failed. Reviews/not-run tests can remain.
- **1**: a failure meets `--fail-on high|medium|low|info`. Severity gating is opt-in; default is `none`.
- **2**: invalid input, unavailable/partial evidence, evaluation error, unverified/mismatched target, or active cleanup failure.

Evidence gaps take precedence over a severity gate. Alignment is `pass / (pass + fail)` only with verified target binding; evidence coverage separately includes reviews and not-run tests in its denominator. Do not turn either number into an overall health/compliance score.

## Development and validation

```powershell
npm run check
npm test
npm run build:site
az bicep build --file .\infra\metadata-reader.bicep --stdout
```

There are no runtime or npm development dependencies. Tests use Node's built-in runner, synthetic Azure/Kubernetes responses, a local loopback HTTP server and mocked mutation/cleanup paths. They do not contact Azure or Kubernetes. The [CI workflow](.github/workflows/validate.yml) covers Node 22/24 on Windows/Linux without Azure credentials.

The native-launcher regression uses PowerShell 7 (`pwsh`) on Windows and Bash on Linux/macOS. Respect your organization's script-execution policy; if a launcher is blocked, use the direct Node CLI instead of changing or bypassing policy.

The optional [cloud metadata Reader Bicep](infra/metadata-reader.bicep) and [Kubernetes read-only role](manifests/reader-clusterrole.yaml) are **not deployed automatically**. The YAML role uses YAML 1.2's JSON syntax so its complete contents and permissions can be validated without a YAML package. Permission grants must be approved separately.

Before changing controls, read [contribution guidance](CONTRIBUTING.md). This toolkit intentionally exposes what remains unproven rather than offering a misleading "all clear."
