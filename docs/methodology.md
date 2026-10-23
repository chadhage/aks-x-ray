# Assessment methodology

## Evidence pipeline

1. Require an explicit platform, subscription, resource group, cluster and kubeconfig context.
2. Read only the context's HTTPS server URL, never the complete kubeconfig or credentials.
3. Read the named ARM cluster through `az aks show` or `az aksarc show`.
4. Compare its documented endpoint with the context hostname. A mismatch stops additional collection and blocks unrelated conclusions. An unsupported alias/proxy or unavailable ARM endpoint remains unverified; there is no bypass that converts it into verified evidence.
5. Resolve the selected controls' dependencies and collect each resource independently with at most three collector workers.
6. Project allowlisted assessment fields before persistence. Keep resource-specific errors instead of treating them as empty resource lists.
7. Evaluate explicit assertions, preserving observation timestamps, JSON pointers and commands.
8. Write JSON, Markdown, a standalone HTML report and SHA-256 hashes.

Matching endpoint hostnames helps detect inventory from different clusters. It is **not cryptographic proof of cluster identity**. Existing kubeconfig trust, DNS, Azure authentication and endpoint certificates remain prerequisites.

## Status contract

| Status | Meaning | Counted as alignment success? |
|---|---|---|
| `pass` | Observed evidence supports this exact assertion | Yes, only in the pass/fail denominator |
| `fail` | Observed evidence contradicts this assertion | No |
| `review` | Intent or independent operational evidence is required | No |
| `unknown` | Required evidence or API fields are unavailable | No |
| `error` | Evaluation or an active measurement could not complete validly | No |
| `notApplicable` | Platform, profile or observed resource set excludes the check | No; excluded from applicable-control denominator |
| `notRun` | Active test deliberately not executed | No; included as an applicable evidence gap |

A partially observed control can report a known failure while also setting `incomplete=true`. It is then excluded from complete evidence coverage and produces exit code 2. A known failure can be investigated even when some observations are unavailable.

Classifications describe the evidence: `adherence`, `deviation`, `conflict`, `missing`, `misconfiguration`, `requires-context` or `insufficient-evidence`. Severity is an operational triage priority, **not CVSS**, exploitability proof or Microsoft severity.

## Recommendation versus universal requirement

Each control turns a selected Microsoft recommendation into a check. A recommendation is not necessarily a requirement for every cluster. Private versus restricted public API access, managed versus alternative telemetry, dedicated service accounts, CPU limits, image pinning, availability zones and single-instance applications can require contextual decisions.

A failure should trigger an owner review and, where appropriate, a documented exception with compensating controls. This version does not use exception files to convert a failed result into a pass. Manual controls do not become passes based on an unverified questionnaire.

Cloud guidance is not automatically a Local requirement. Cloud-only controls are marked not applicable on Local; the Local baseline and Arc security guidance provide the appropriate architecture context. Linux-specific security checks exclude explicitly Windows workloads. OS is derived from pod OS/node selectors or observed pod-to-node placement; ambiguous applicability stays unknown.

## Scoring

- Alignment: `pass / (pass + fail)`, rounded to the nearest whole percent, suppressed when the target binding is unverified or there are no evaluated controls.
- Evidence coverage: complete pass/fail controls divided by **all applicable controls**, including reviews, unknowns, errors and not-run active tests.
- Neither number is a security/compliance/availability score. Read them alongside the actual scope and evidence gaps.

An empty list can make a workload-specific check not applicable; it cannot establish adherence. Empty node lists fail readiness. Absent API fields are not inferred false or true merely to obtain a verdict. Collection errors are preserved even when other categories succeed.

## Data handling

Default collection does not request Secrets, ConfigMaps, application logs, mounted files, environment values, container commands, arbitrary annotations or kubeconfig credentials. Event messages and probe HTTP headers are omitted. Service-account token references and hostPath locations are omitted. Labels are retained to evaluate PDB/policy matching and can themselves contain sensitive identifiers; projection is **not a guarantee that all possible secrets have been removed from badly labelled resources**.

Raw stdout is held transiently in the collector process and projected before persistence. Raw stderr is not written to artifacts; errors retain a class, exit code and instruction to rerun the recorded command locally. Malformed JSON is reported without copying its potentially sensitive contents.

Artifacts contain private cluster inventory. POSIX creation modes are restrictive; Windows ACLs are inherited. Do not publish real reports on a public website, paste them into public issues, or commit them. Committed report examples use only synthetic data.

## Reproducibility and limitations

- Sources have individual timestamps. The cluster can change during or after collection.
- Kubernetes object defaults are used only where the API defines them, such as an omitted Deployment replica count of one.
- Full policy unions, cloud effective routes, private DNS, admission assignments, federation, CVEs, log ingestion, backups and application semantics are not inferred from enablement flags.
- The catalogue digest covers categories, assertions and source metadata. Keep the matching repository revision to reassess saved evidence.
- File hashes detect accidental changes but do not prove a collector's identity or prevent a malicious actor from replacing files and hashes together.
- Schemas document the interchange contract. Dependency-free runtime validators additionally check category completeness, source shapes, matching revisions and measurement semantics.

For operational acceptance, pair the output with the evidence requests in [coverage boundaries](coverage.md), and scope any intrusive or application-specific work through [active testing](active-testing.md).
