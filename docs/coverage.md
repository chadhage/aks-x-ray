# Platform coverage and evidence boundaries

The [catalogue](../catalog/controls.json) lists the implemented checks and manual reviews. The [HTML page](../site/index.html) lists and filters the same controls. These categories do not cover every AKS feature or threat.

The new [diagnosis engine](diagnosis.md) makes that catalogue an optional strategy. Its primary model is a resource/identity graph and reconciled exposure/path/validation claims. Namespace and configuration-area groupings are derived views.

## Graph and path coverage

| Surface | Implemented evidence | Boundary |
|---|---|---|
| Cross-subscription resources | Explicitly approved ARG inventory and linked resources with canonical ARM IDs | Reader-filtered visibility is not complete asset discovery; no implicit subscription expansion |
| Azure identities | Control-plane/kubelet identity references, UAI client/principal metadata, role definitions and assignment scopes | External directory membership, deny assignments and PIM are not resolved or presumed |
| Kubernetes identities | Namespace-correct SA/Role/Binding relationships and native SA group contracts | Same-named subjects do not merge across clusters; external Entra groups are not guessed |
| Federation | Exact issuer/subject/audience/client-ID metadata joins | No token values, credential minting or live token-exchange proof |
| Attack hypotheses | Workload-token-to-secret, federated workload/Azure identity data access and AKS admin-credential issuance patterns | Initial compromise is unknown unless explicitly assumed; this is not an exhaustive escalation/CVE model |
| Validation | Current-subject permission reviews, scoped privileged-Pod dry-run and separately approved owned canaries | Results do not validate another identity, namespace, production workload or complete attack chain |
| Reconciliation | Exact semantic/scope deduplication, contributions, contradictions, independent risk/confidence | Similar titles are not sufficient to merge assertions; source hashes do not attest authenticity |

Configured exposure, plausible exploitability and validated behavior are distinct evidence tiers, not interchangeable severity labels. Missing/partial data, conflicting snapshots and unexecuted validation remain visible; no strategy produces a default healthy score.

## Supported adapters

| Surface | Current implementation | Explicit boundary |
|---|---|---|
| Cloud AKS Standard | `az aks` metadata + optional explicitly authorized Kubernetes context; scoped supplemental strategies | Dependency discovery is bounded and does not enumerate every workload relationship |
| Cloud AKS Automatic | Same metadata adapter; recognizes `sku.name=Automatic` | Operator-managed system-pool and zone checks remain review rather than pass |
| AKS enabled by Arc on Azure Local | `az aksarc show` + common Kubernetes inventory | Supported documented Local API shape is required; no cloud-only property assumptions |
| Local ARM endpoint unavailable | Kubernetes inventory can still be collected if reachable | Binding/ARM controls stay unknown, alignment is suppressed and exit code is 2 |
| Legacy AKS on HCI/Windows Server, bare metal, arbitrary Arc Kubernetes | No dedicated metadata adapter | Do not relabel these as Local and interpret unrecognized fields as compliance |
| Linux application security | Container/pod inheritance and observed OS applicability | Ambiguous OS stays unknown; profile content and runtime enforcement need review |
| Windows applications | Common node/pod/resources/RBAC checks and HostProcess detection | Linux privilege, capabilities, seccomp and non-root checks are not applied |
| Active runner | Isolated Linux amd64 synthetic pods | Requires a compatible schedulable node, approved image access and policy permissions |

## Assessment evidence still required

| Architectural surface | Automatically observed | Independent evidence needed |
|---|---|---|
| Control plane | Context/ARM endpoint correlation, configured cloud exposure/tier | Endpoint certificates, DNS aliases/proxies, public/private reachability and administrative access |
| Identity | Tenant/subscription scope, Entra/local-account flags, OIDC pairing, service accounts, Azure inherited assignments and Kubernetes role/binding inventory, broad sensitive grants | Complete effective grants, custom/aggregated privileges, deny assignments, conditions, group membership, PIM, break-glass and workload federation |
| Compute | Node conditions, pool configuration, versions, declared zones/taints | Supported SKU/OS windows, physical/VM failure domains, NUMA/GPU drivers, capacity under failure |
| Network | CIDRs, policy manifests, Ingress TLS, services/EndpointSlices; approved subnet/NSG/route metadata and declared Internet-wide management-port rules | Complete IPAM, peering, UDR/NSG/firewall effective decisions and priorities, SNAT, metadata isolation, DNS/LocalDNS, proxies, Cilium enforcement |
| Ingress/service mesh | Kubernetes Ingress declarations and service readiness | Gateway API, Application Gateway for Containers, WAF rules, mesh mTLS, certificates and real client transactions |
| Application security | Privilege/host declarations, read-only roots, token automount inheritance, approved registry hosts, webhook settings, scoped Defender states and Containers plan | Image CVEs/signatures/SBOM, scan freshness, effective admission, token necessity, secret delivery/rotation and runtime detection coverage |
| Workloads | Resources/probes, Deployment availability, HPA bounds, explicit pod failures | Semantic probes, startup behavior, sidecar semantics, scheduler saturation, VPA/KEDA/HPA interaction and representative performance |
| Reliability | Replica/PDB/topology declarations and drain-blocking configuration | Actual placement, readiness during drains, zone/site failure, upgrade surge and complete dependency recovery |
| Storage | PVC state, Azure Disk binding, CSI/reclaim-policy inventory | Backend health/encryption, attachment/IOPS/latency, expansion, access modes, application-consistent restore |
| Observability | Audit destination configuration, metrics/log enablement, warning reasons | Recent ingestion, retention, access, alert delivery, dashboard/SLO correctness and audit completeness |
| Governance | Policy add-on, quotas, restricted PSA labels, defaults and scoped Policy compliance/exemption states | Complete assignment intent, effective enforcement, exemption approval, evaluation recency, deployment safeguards, GitOps ownership and drift |
| Cost/capacity | Autoscaler/NAP enablement, configured bounds and existing scoped Advisor recommendations | Measured resource use, throttling, pricing, commitments, reservations/Spot suitability, failure and growth headroom |
| Dependencies | Approved ACR admin, vault recovery/RBAC, storage transport/public defaults, subnet/NSG metadata and explicit unsupported-type inventory | Complete dependency discovery, all API settings, data-plane content/access, effective networking, secret/key rotation and recovery validation |
| Lifecycle | Upgrade/OS channels and separate maintenance schedules | Current official supported-version/OS tables, upgrade rehearsals, image support and recovery plans |
| Backup/DR | Manual review only | Successful validated restores, isolated copies, RPO/RTO, regional/site/data/dependency failover |
| Azure Local | Provisioning and documented control-plane count | Host/Arc/resource-bridge health, certified hardware, firmware, Secure Boot/TPM/BitLocker, Storage Spaces Direct, rack topology and disconnected operations |

## Known interpretation constraints

- CIDR comparison supports IPv4 and IPv6 but compares only the reported pod/service ranges and DNS IP. It does not discover all external networks.
- A default-deny manifest does not prove effective isolation: NetworkPolicy rules are additive and an engine must enforce them.
- PDB coverage supports match labels and set-based selectors. A target count not reconciled with the observed Deployment/StatefulSet set is unknown; it does not receive a passing result.
- Readiness of an EndpointSlice is not a successful client connection. Unknown endpoint readiness stays unknown.
- Workload resource checks include regular/init containers and template/runtime observations; ephemeral containers are included for security but not resource requests/limits.
- Job/CronJob workloads are excluded from long-running probe recommendations. Generic probes on sidecars still require owner interpretation.
- Diagnostics routing to `kube-audit-admin` is a configured audit path, not proof of full audit coverage or successful ingestion.
- Role/binding and Azure-assignment inventory does not establish every custom privilege path, group membership, external identity decision, conditional grant or effective data-plane permission.
- Dependency reference traversal and `relatedResourceIds` are explicit scope inputs, not proof that every dependency was discovered. Unsupported types and unscored settings remain review; caps and out-of-scope references are errors.
- Scenario and 1-100/null scores are project-defined rubrics. Per-area/pillar/namespace coverage describes implemented assertions only, not the fraction of every possible platform setting assessed.
- Warnings and versions are snapshots, not complete historical incident or support-window verdicts.

Use the Microsoft references attached to each rule and collect the additional evidence listed here before drawing conclusions about those areas. Static inventory alone does not cover them.
