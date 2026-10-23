# Permissions and prerequisites

## Azure management plane

Collection uses your existing Azure CLI identity and explicit subscription GUIDs. `audit` additionally requires a tenant, approved subscription allowlist and `authorization.readOnly=true`. This records invoker consent; it does not grant access. Only `login` invokes `az login --tenant ... --use-device-code --output none`; Azure CLI manages the credential cache and normal login state. Collection never invokes admin credential download, `az account set`, role grants or implicit authentication.

Cloud reads:

- `az aks show`
- `az aks nodepool list`
- `az monitor diagnostic-settings list --resource <returned-cluster-resource-id>`
- `az aks maintenanceconfiguration list`

Invoker-selected audit reads additionally include:

| Strategy | CLI / required read surface |
|---|---|
| `azure` | `az account show --subscription ...` for every approved subscription; exact target ARM reads |
| `iam` | `az role assignment list --scope ... --include-inherited`; no directory enrichment |
| `iam-inventory` | Explicitly approved subscription-wide assignment and role-definition reads; federation reads only for approved observed managed identities |
| `resource-graph` | `az graph query --graph-query Resources --subscriptions ...` with bounded continuation pages; no implicit subscriptions or extension installation |
| `policy` | `az policy state list --resource ... --all`; approved Policy Insights query permissions may be needed |
| `defender` | `az security pricing show --name Containers` and `az security assessment list` in approved subscriptions |
| `advisor` | `az advisor recommendation list` in approved subscriptions, without `--refresh` |
| `dependencies` | `az resource show --ids ...` for approved explicit/allowlisted linked resources, including any approved dependency subscriptions |

Defender/Advisor list commands can require subscription-level metadata visibility even though persisted recommendations are target-filtered. The cluster-only Bicep Reader grant is not sufficient for every supplemental strategy or dependency. Use approved scoped/custom metadata roles; do not broaden grants automatically to eliminate unknowns. Denials are evidence gaps. No value-reading Key Vault, Storage, ACR or Kubernetes secret permissions are requested.

Local reads:

- `az aksarc show` with the existing extension and your configured Azure authentication.

Azure **Reader** on the applicable cluster resource scope is a reasonable metadata starting point; validate your organization's deny assignments and policies. Local provisioned cluster instances can be extension resources under an Arc connected-cluster resource; grant the approved read scope for that actual resource hierarchy. Disconnected management-plane access can be unavailable even while Kubernetes is reachable; that remains an evidence gap.

The optional [Bicep template](../infra/metadata-reader.bicep) grants Reader on one **existing cloud AKS cluster**. It grants no Kubernetes access and is never invoked by collection. An authorized administrator can review it, run a what-if, and deploy it through the approved infrastructure deployment process. Do not grant subscription-wide rights merely to suppress assessment unknowns.

## Kubernetes data plane

The collector requires `get`/`list` only for selected category dependencies and explicitly authorized supplemental Kubernetes inventory. This includes Roles, RoleBindings, ClusterRoles and admission-webhook configurations. See the complete [reader ClusterRole](../manifests/reader-clusterrole.yaml). It has no wildcard resources/verbs and cannot read secret/config-map values, logs, proxy endpoints or exec sessions.

For Kubernetes-RBAC-authorized subjects, an administrator may review and install the role:

```powershell
# Optional administrator setup: this changes RBAC, unlike collection.
kubectl --context "<target-context>" create --filename .\manifests\reader-clusterrole.yaml
```

Binding a subject is deliberately separate. Use your organization's approved identity and scoping procedure; do not bind anonymous users or `system:authenticated` globally. Namespace-only assessment can use appropriately scoped Roles for namespaced reads, while cluster-wide metadata/control-plane reads still need their corresponding permissions.

**Azure RBAC for Kubernetes authorization is distinct from Kubernetes RBAC.** A Kubernetes role file alone does not grant every Entra user access in every AKS authorization mode. The built-in Azure Kubernetes Service RBAC Reader may intentionally exclude RBAC details. Have the cluster administrator approve the actual authorization model and only the needed data actions; missing cluster-role-binding visibility will correctly leave the privileged-access review unknown.

The tool records denied APIs independently. It does not escalate to cluster-admin, impersonate another identity, retry with admin credentials, or quietly omit denied checks.

The `kubernetes` strategy can be omitted entirely. No `kubectl` command is then issued, reports identify ARM-only binding, and Kubernetes checks remain unrun. That evidence cannot authorize the active runner.

## Permission-aware diagnosis stages

The new [diagnosis workflow](diagnosis.md) separates collection consent from analysis selection and validation approval. Graph or attack-path selection does not authorize subscription-wide IAM, inventory or mutation.

Non-mutating stages need explicit context/namespace/test/expiry approval and supported self-subject identity/authorization APIs. These POST reviews return the current subject's permission decision, not secret contents; no impersonation permission is needed or requested. Admission probes additionally require a positive Pod-create permission review and use server-side dry-run only.

Intrusive stages require separate exact-context/suite/expiry approval and a fresh complete permission matrix for the exact prepared owned namespace. API grant declarations alone are not used as proof. Identity/context drift, denied/unknown permissions, expiry or validation limits block new activity. Expiry during execution cancels test work while allowing only the existing ownership-checked cleanup obligation.

Permissions and approval checks are point-in-time observations, not locks. A later admission or authorization rejection remains an error and cannot be turned into a successful control test.

## Active-test permissions

The read-only role intentionally **cannot** run active tests. Those need separately approved permissions to:

- Create a new Namespace and read/delete that exact owned Namespace.
- Create ResourceQuota, NetworkPolicy, Service and Job resources in it.
- Get/list the generated pods/jobs/service and inspect pod readiness.
- Create `pods/exec` and `pods/portforward` sessions for the synthetic workload.
- Submit a Pod **server-side dry-run** to exercise restricted admission.

RBAC cannot scope namespace-creation permission to an already nonexistent namespace in the same way as a namespace-local Role. Use a controlled testing identity, an admission policy limiting the allowed test namespace prefix/labels where appropriate, an approved maintenance window and supervision. The runner checks ownership; permissions still require separate review and approval.

No permission grant, extension install or live-cluster mutation is performed by this repository's offline tests or CI.
