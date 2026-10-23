# Assessment methodology

For the new graph/risk-first engine, see [diagnosis methodology and reconciliation](diagnosis.md). The existing catalogue, assertion statuses and higher-is-better adherence rubric below remain the optional `configuration` strategy. They are not the organizing model or risk scale of a diagnosis.

## Evidence pipeline

1. For `audit`, validate the invoker's tenant, subscription allowlist, targets, strategies, read-only approval and intended scenario before any external command. Legacy `collect` requires an explicit platform, subscription, resource group, cluster and context.
2. Verify each listed subscription's enabled CLI account metadata against the explicit tenant before reading target inventory. Only the separate `login` command performs device authentication.
3. When Kubernetes collection is authorized, read only the context's HTTPS server URL, never complete kubeconfig or credentials.
4. Read the named ARM cluster through `az aks show` or `az aksarc show` and compare its exact resource ID with the named subscription/resource-group/cluster target.
5. Compare its documented endpoint with the context hostname. A mismatch stops additional collection and blocks unrelated conclusions. An unsupported alias/proxy or unavailable ARM endpoint remains unverified; there is no bypass that converts it into verified evidence. With no Kubernetes authorization, tenant/account/ARM checks can establish an explicitly labelled `arm-only` binding, not a cross-plane binding.
6. Resolve selected control dependencies and authorized supplemental sources. Withheld strategies issue no commands and become explicit `notRun` gaps. Collect with at most three workers; traverse approved dependency references serially with deduplication and the configured resource cap.
7. Project allowlisted assessment fields before persistence. Keep resource-specific errors and successful partial dependency metadata instead of treating failures as empty resource lists.
8. Evaluate explicit assertions, preserving observation timestamps, JSON pointers and commands. Reevaluate namespaced controls separately for each selected or observed namespace.
9. Compute documented 1-100/null scores and write JSON, Markdown, a standalone HTML report and SHA-256 hashes. Multi-target audits additionally write a fleet index.

Matching endpoint hostnames and CLI account metadata helps detect inventory from different targets. It is **not cryptographic proof of cluster identity or tenant ownership**. Existing kubeconfig trust, DNS, current Azure authentication, delegated-access design and endpoint certificates remain prerequisites.

## Status contract

| Status | Meaning | Counted as alignment success? |
|---|---|---|
| `pass` | Observed evidence supports this exact assertion | Yes, only in the pass/fail denominator |
| `fail` | Observed evidence contradicts this assertion | No |
| `review` | Intent or independent operational evidence is required | No |
| `unknown` | Required evidence or API fields are unavailable | No |
| `error` | Evaluation or an active measurement could not complete validly | No |
| `notApplicable` | Platform, profile or observed resource set excludes the check | No; excluded from applicable-control denominator |
| `notRun` | A required collection strategy or active test was deliberately not authorized | No; included as an applicable evidence gap |

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

### Project-defined 1-100 configuration rubric

This rubric is not an official Microsoft or Azure WAF assessment score, CVSS, exploitability estimate, certification or overall health verdict.

- Only complete `pass`/`fail` assertions on a verified target receive a number. `review`, `unknown`, `error`, `notApplicable`, `notRun`, partial results and unverified/mismatched targets have `score: null`.
- A scalar pass scores **100** and scalar failure **1**, never zero.
- When a control has complete checked/deviation counts, its score is `round(1 + 99 * (checked - deviations) / checked)`. For example, two adherent observations out of three score **67**. Counts are validated rather than silently clamped.
- Aggregate scores are rounded weighted means of scored controls, not of individual pods: **high=5, medium=3, low=1, info=1**. The overall score counts each control once. A control may contribute to more than one WAF pillar, but is not duplicated within a pillar.
- Every aggregate also reports applicable, scored and unscored counts, control IDs and `coveragePercent = round(scored / applicable * 100)`. No applicable/scored observations produces `null`, not a default healthy result.
- Area-to-pillar mappings are explicit in [the category catalogue](../catalog/categories.json). The five pillars are reliability, security, cost optimization, operational excellence and performance efficiency.
- Namespace groups rerun namespaced assertions against that namespace's evidence. A failure in one namespace is not copied into every namespace. Purely global controls are excluded; namespace checks may still need global roles, policy engines or node OS evidence.
- A known failing dependency can remain `fail, incomplete=true` when companion settings are missing. Its field gaps are retained, and it is unscored.
- The CLI validator and offline browser use the same scoring runtime and recompute individual, area, pillar and namespace scores. Imported score edits or omitted namespace controls are rejected.

A score of 100 with low coverage says only that the **scored subset** met those assertions. It can coexist with unscored high-risk reviews or critical evidence gaps. Always read severity, actual findings, scope and coverage together. Unsupported resource types and additional settings remain explicit dependency review, not invented numeric judgments.

Audits record scenario-specific API intent, replica and zone thresholds, and optional approved registry hosts. These are operator requirements, not generic Microsoft workload SLOs. Omitted optional thresholds use documented production/development defaults; explicit nulls and typos are rejected.

An empty list can make a workload-specific check not applicable; it cannot establish adherence. Empty node lists fail readiness. Absent API fields are not inferred false or true merely to obtain a verdict. Collection errors are preserved even when other categories succeed.

## Data handling

Default collection does not request Secrets, ConfigMaps, application logs, mounted files, environment values, container commands, arbitrary annotations or kubeconfig credentials. Event messages and probe HTTP headers are omitted. Service-account token references and hostPath locations are omitted. Labels are retained to evaluate PDB/policy matching and can themselves contain sensitive identifiers; projection is **not a guarantee that all possible secrets have been removed from badly labelled resources**.

Raw stdout is held transiently in the collector process and projected before persistence. Raw stderr is not written to artifacts; errors retain a class, exit code and instruction to rerun the recorded command locally. Malformed JSON is reported without copying its potentially sensitive contents.

Artifacts contain private cluster inventory. POSIX creation modes are restrictive; Windows ACLs are inherited. Do not publish real reports on a public website, paste them into public issues, or commit them. Committed report examples use only synthetic data.

## Reproducibility and limitations

- Sources have individual timestamps. The cluster can change during or after collection.
- Device login is explicit and terminal-only; Conditional Access can deny device flow. Authentication errors never trigger fallback credentials, context switching or broader scope.
- Dependency traversal is limited to allowlisted ARM references plus invoker-supplied IDs. It does not infer every application connection, secret-backed reference, peering relationship, external SaaS dependency or data-plane setting. Unapproved subscription references and resource caps are errors.
- Defender and Advisor CLI reads may enumerate metadata within the explicitly approved subscriptions before filtering to target/dependency IDs. Policy collection queries the target only. No new scans, recommendations or remediation are triggered.
- Kubernetes object defaults are used only where the API defines them, such as an omitted Deployment replica count of one.
- Full policy unions, cloud effective routes, private DNS, admission assignments, federation, CVEs, log ingestion, backups and application semantics are not inferred from enablement flags.
- The catalogue digest covers categories, assertions and source metadata. Keep the matching repository revision to reassess saved evidence.
- File hashes detect accidental changes but do not prove a collector's identity or prevent a malicious actor from replacing files and hashes together.
- Schemas document the interchange contract. Dependency-free runtime validators additionally check category completeness, source shapes, matching revisions and measurement semantics.

For operational acceptance, pair the output with the evidence requests in [coverage boundaries](coverage.md), and scope any intrusive or application-specific work through [active testing](active-testing.md).
