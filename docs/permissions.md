# Permissions and prerequisites

## Azure management plane

Collection uses your existing Azure CLI identity and an explicit subscription GUID. It never obtains admin credentials or changes account settings.

Cloud reads:

- `az aks show`
- `az aks nodepool list`
- `az monitor diagnostic-settings list --resource <returned-cluster-resource-id>`
- `az aks maintenanceconfiguration list`

Local reads:

- `az aksarc show` with the existing extension and your configured Azure authentication.

Azure **Reader** on the applicable cluster resource scope is a reasonable metadata starting point; validate your organization's deny assignments and policies. Local provisioned cluster instances can be extension resources under an Arc connected-cluster resource; grant the approved read scope for that actual resource hierarchy. Disconnected management-plane access can be unavailable even while Kubernetes is reachable; that remains an evidence gap.

The optional [Bicep template](../infra/metadata-reader.bicep) grants Reader on one **existing cloud AKS cluster**. It grants no Kubernetes access and is never invoked by collection. An authorized administrator can review it, run a what-if, and deploy it through the approved infrastructure deployment process. Do not grant subscription-wide rights merely to suppress assessment unknowns.

## Kubernetes data plane

The collector requires `get`/`list` only for the resources declared by the selected category dependencies. See the complete [reader ClusterRole](../manifests/reader-clusterrole.yaml). It has no wildcard resources/verbs and cannot read secret/config-map values, logs, proxy endpoints or exec sessions.

For Kubernetes-RBAC-authorized subjects, an administrator may review and install the role:

```powershell
# Optional administrator setup: this changes RBAC, unlike collection.
kubectl --context "<target-context>" create --filename .\manifests\reader-clusterrole.yaml
```

Binding a subject is deliberately separate. Use your organization's approved identity and scoping procedure; do not bind anonymous users or `system:authenticated` globally. Namespace-only assessment can use appropriately scoped Roles for namespaced reads, while cluster-wide metadata/control-plane reads still need their corresponding permissions.

**Azure RBAC for Kubernetes authorization is distinct from Kubernetes RBAC.** A Kubernetes role file alone does not grant every Entra user access in every AKS authorization mode. The built-in Azure Kubernetes Service RBAC Reader may intentionally exclude RBAC details. Have the cluster administrator approve the actual authorization model and only the needed data actions; missing cluster-role-binding visibility will correctly leave the privileged-access review unknown.

The tool records denied APIs independently. It does not escalate to cluster-admin, impersonate another identity, retry with admin credentials, or quietly omit denied checks.

## Active-test permissions

The read-only role intentionally **cannot** run active tests. Those need separately approved permissions to:

- Create a new Namespace and read/delete that exact owned Namespace.
- Create ResourceQuota, NetworkPolicy, Service and Job resources in it.
- Get/list the generated pods/jobs/service and inspect pod readiness.
- Create `pods/exec` and `pods/portforward` sessions for the synthetic workload.
- Submit a Pod **server-side dry-run** to exercise restricted admission.

RBAC cannot scope namespace-creation permission to an already nonexistent namespace in the same way as a namespace-local Role. Use a controlled testing identity, an admission policy limiting the allowed test namespace prefix/labels where appropriate, an approved maintenance window and supervision. The runner checks ownership; permissions still require separate review and approval.

No permission grant, extension install or live-cluster mutation is performed by this repository's offline tests or CI.
