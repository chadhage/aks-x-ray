# Platform coverage and evidence boundaries

The [catalogue](../catalog/controls.json) lists the implemented checks and manual reviews. The [HTML page](../site/index.html) lists and filters the same controls. These categories do not cover every AKS feature or threat.

## Supported adapters

| Surface | Current implementation | Explicit boundary |
|---|---|---|
| Cloud AKS Standard | `az aks` metadata + explicit Kubernetes context | External Azure dependencies are not fully enumerated |
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
| Identity | Entra/local-account/RBAC flags, OIDC pairing, service-account declarations, cluster-admin binding inventory | Effective Azure/Kubernetes grants, group membership, PIM, break-glass and workload federation |
| Compute | Node conditions, pool configuration, versions, declared zones/taints | Supported SKU/OS windows, physical/VM failure domains, NUMA/GPU drivers, capacity under failure |
| Network | CIDRs, policy manifests, Ingress TLS declarations, services/EndpointSlices | VNet/subnet IPAM, peering, UDR/NSG/firewall effective decisions, SNAT, metadata isolation, DNS/LocalDNS, proxies, Cilium enforcement |
| Ingress/service mesh | Kubernetes Ingress declarations and service readiness | Gateway API, Application Gateway for Containers, WAF rules, mesh mTLS, certificates and real client transactions |
| Application security | Privilege/host access declarations and image-reference versioning | Image CVEs/signatures/SBOM, registry controls, admission assignments, secret delivery/rotation and runtime detections |
| Workloads | Resources/probes, Deployment availability, HPA bounds, explicit pod failures | Semantic probes, startup behavior, sidecar semantics, scheduler saturation, VPA/KEDA/HPA interaction and representative performance |
| Reliability | Replica/PDB/topology declarations and drain-blocking configuration | Actual placement, readiness during drains, zone/site failure, upgrade surge and complete dependency recovery |
| Storage | PVC state, Azure Disk binding, CSI/reclaim-policy inventory | Backend health/encryption, attachment/IOPS/latency, expansion, access modes, application-consistent restore |
| Observability | Audit destination configuration, metrics/log enablement, warning reasons | Recent ingestion, retention, access, alert delivery, dashboard/SLO correctness and audit completeness |
| Governance | Policy add-on, quotas, PSA/default-limit inventory | Assignments, enforcement/exemptions, compliance state, deployment safeguards, GitOps ownership and drift |
| Cost/capacity | Autoscaler/NAP enablement and configured bounds | Measured resource use, throttling, pricing, commitments, reservations/Spot suitability, failure and growth headroom |
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
- The cluster-admin inventory does not enumerate every custom privilege path, RoleBinding, external identity provider or Azure role assignment.
- Warnings and versions are snapshots, not complete historical incident or support-window verdicts.

Use the Microsoft references attached to each rule and collect the additional evidence listed here before drawing conclusions about those areas. Static inventory alone does not cover them.
