# Authorized active testing

## Scope and approval

Obtain written resource-owner authorization and an approved scope/window. Read [Microsoft's Azure penetration-testing policy](https://learn.microsoft.com/azure/security/fundamentals/pen-testing) and its linked authoritative rules of engagement. Resource-owner approval does not permit DoS, unauthorized access, excessive traffic or actions against other tenants.

These tests send DNS and HTTP requests to generated resources and check Pod admission with a server-side dry-run. They do **not** perform exploitation, credential dumping, lateral movement, privilege escalation, node drains/deletion, disruption tests, a backup restore, or denial-of-service testing.

Before use:

1. Review [permissions](permissions.md) and the generated resource design in [the active runner](../src/active.mjs).
2. Test the runner against a nonproduction test cluster. This implementation has offline/mocked tests but has **not been validated on a live cloud or Local cluster**.
3. Collect real evidence with verified context-to-ARM endpoint binding. For audits, authorize the `kubernetes` strategy first; an ARM-only binding cannot authorize active tests. Synthetic evidence, mismatched targets and unresolved prior cleanup are rejected. Tenant-bound runs recheck all approved subscription account metadata before issuing any Kubernetes command.
4. Approve the official `mcr.microsoft.com/azure-cli:azurelinux3.0` runtime. The [source registry](../catalog/sources.json) pins its reviewed MCR manifest digest; its image configuration is Linux amd64 and its official RPM requires Python. Review the pinned image's currency and vulnerability evidence before use. Updating a tag without revalidating the new digest is not sufficient. There is no automatic arbitrary-image override.
5. Confirm that Linux amd64 nodes have capacity and that your admission policies permit the constrained resources. No policy is disabled or bypassed.

## Execute

For permission-aware strategy orchestration, use [diagnosis stage approvals](diagnosis.md#permission-aware-stages). That path requires fresh exact-namespace permission review, binds the prepared UUID to execution, rechecks actor/context, and enforces expiry throughout test activity while preserving owned cleanup. The command below remains the standalone legacy compatibility runner; it does not imply that an audit config or saved report authorizes it.

```powershell
node .\bin\aks-xray.mjs active `
  --input ".\artifacts\baseline\evidence.json" `
  --suite all `
  --authorize-active `
  --confirm-context "the-exact-collected-context" `
  --requests 40 --concurrency 2 --duration-seconds 10 `
  --latency-budget-ms 2000 --error-budget-percent 0 `
  --output ".\artifacts\authorized-smoke"
```

`--suite` accepts `connectivity`, `end-to-end`, `load`, `security` or `all`. Neither `audit`, `collect`, read-only approval nor selecting `active-validation` authorizes mutations. For multi-target audit output, select one exact `cluster-NNN/evidence.json` and confirm that target's context; there is no fleet-wide active-test shortcut.

## Isolation and safety bounds

- Only an unpredictable `aks-xray-<run-id>` namespace is created; existing namespaces are never reused.
- Ownership is recorded in two labels, a run ID and the namespace UID.
- Two small Jobs use non-root execution, read-only root filesystems, dropped capabilities, no projected service-account token and explicit resource requests/limits.
- Jobs have `activeDeadlineSeconds=240`, no retries and a 60-second post-completion TTL. If cleanup fails, workload lifetime is still bounded by the job controller, assuming a healthy control plane.
- The namespace receives a resource quota, default-deny policies, a narrowly scoped synthetic HTTP allow rule and DNS-port egress. DNS allows TCP/UDP 53 to accommodate DNS/LocalDNS implementations; this is not an audit of your existing DNS policy.
- The Service is ClusterIP only. Port-forward binds **127.0.0.1** with an automatically selected local port.
- The HTTP destination is fixed to that owned port-forward. No arbitrary URL, external ingress listener or production application is loaded.
- Load is capped at 200 total attempts, four workers, 30 seconds of request phase and at least 100 ms pacing per worker (nominal ceiling about 40 attempts/second). Setup and cleanup have separate bounded command deadlines.
- Readiness polling is capped at 90 seconds. Images may fail to pull or be denied; these are explicit errors, not test passes.
- The admission negative test uses `--dry-run=server`. Only a specific restricted-PSA rejection counts as successful denial; an unrelated Forbidden/timeout is an error.

Ctrl+C/SIGTERM requests cancellation and cleanup. Power loss, forced process termination, filesystem errors or a broken control plane can prevent cleanup; inspect the persisted run record. Active evidence/report snapshots are updated as the run progresses.

Strategy-enabled audits additionally retain per-action pending/cleanup snapshots under `validations/`. A new diagnosis can be rendered offline from saved evidence; that action never reruns these tests or reuses cached permission reviews to authorize new mutations.

## What the measurements establish

| Suite | Measured result | Not measured |
|---|---|---|
| Connectivity | A synthetic probe resolves and reaches its synthetic service | All pod-to-pod paths, cross-namespace deny behavior, external egress, NSG/UDR/firewall or IMDS isolation |
| HTTP (`end-to-end`) | Three expected-marker responses through API port-forward | Real ingress, WAF, TLS, identity or a business transaction |
| Load smoke | Actual samples meet the recorded error/p95 budgets | Application production capacity, node/network saturation, endurance, autoscaler performance or Microsoft SLO adherence |
| Security admission | Restricted PSA rejects a privileged server dry-run in the test namespace | Existing namespace enforcement, effective least privilege, vulnerability absence or a full penetration test |

Latency includes the client/API port-forward path. p95 is **nearest rank** over all attempt latencies; unsuccessful attempts also count in the error denominator. A run with no requests, malformed measurements or out-of-bounds limits cannot pass.

## Cleanup and recovery

The runner closes its exact port-forward process and re-reads the owned namespace. It verifies managed-by label, run ID and recorded UID before deleting that namespace. It never deletes by wildcard, strips finalizers or removes unrelated resources.

When cleanup fails:

1. Keep `evidence.json`, `assessment.json` and `active-manifest.json`.
2. Read `activeRun.namespace`, `activeRun.runId`, `activeRun.namespaceUid` and `activeRun.cleanup.error`.
3. Reconfirm the **exact context**, namespace UID and both ownership labels through your approved administration process.
4. If ownership is verified, have an authorized operator delete only that namespace. If ownership differs, stop and investigate.
5. Confirm namespace deletion and retain the recovery evidence. Do not edit a failed cleanup record into a successful one; recollect a new baseline after remediation.

A cleanup error returns exit code 2 and is displayed prominently even if measurements passed.

## Application performance and recovery testing

For application performance testing, use a separately approved test plan following [Azure Load Testing guidance](https://learn.microsoft.com/azure/load-testing/overview-what-is-azure-load-testing):

- Define representative application transactions, authentication, data isolation and expected traffic.
- Set owner-approved latency/error/throughput goals and explicit stop conditions; these are workload SLOs, not generic Microsoft thresholds.
- Plan realistic baseline, controlled ramp, burst and endurance phases within permitted resource/traffic budgets. Do not implement DoS or indiscriminate saturation.
- Capture time-series CPU/memory, throttling/OOM, scheduler, HPA/KEDA/VPA behavior, storage/network latency and control-plane signals.
- Keep production/customer data protected and validate cleanup/cost ceilings.
- Plan recovery, upgrade, failover, backup-restore and security tests separately, with explicit approval and rollback.

Attach those results to the manual controls rather than claiming the synthetic smoke test substitutes for them.
