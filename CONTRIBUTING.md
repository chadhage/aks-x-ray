# Contributing

## Add or change a control

1. Start from current **official Microsoft** documentation, not a third-party checklist.
2. Register the exact source URL, scope and review date in [the source registry](catalog/sources.json). Public Microsoft Learn references are currently the enforced allowlist.
3. State a narrow, testable assertion and its caveats in [the control catalogue](catalog/controls.json).
4. Declare category, platform, profile, evidence dependencies, operational severity and failure classification.
5. Use a manual review when static data cannot establish the claim. Never infer support expiration from a version comparison, backup recovery from installation, or effective policy from an enabled flag.
6. Extend an allowlisted projection/collector only when necessary. Do not add secret values, logs, arbitrary exec or mutation to passive collection.
7. Use red/green TDD: first add focused positive/negative/boundary assertions and run them against the current implementation to demonstrate the missing behavior. Then implement the evaluator while preserving unknown/partial/error behavior, and rerun those tests until they pass.
8. Update the narrowly enumerated reader role and schemas when the evidence contract changes.
9. Update directly related documentation and the catalogue version/review metadata. The digest automatically changes with catalogue contents; old evidence requires its matching revision.

## Validate

```powershell
npm run check
npm test
npm run build:site
node --test --experimental-test-coverage
```

The [getting-started homepage](site/index.html), [sample HTML report](site/sample.html) and synthetic JSON example are generated and committed. Do not edit them by hand; edit [the HTML template](site/template.html), [styles](site/styles.css), [browser script](site/app.js) or [demo fixture](examples/demo.mjs), then rebuild. Keep the demo timestamp fixed so builds are deterministic. The homepage must not embed an assessment; only the explicit sample link opens synthetic results.

Use only Clawpilot theme variables for component colors, local system fonts and inline dependencies. Browser imports must treat inventory as text, reject invalid report shapes and never execute source-provided HTML or URLs. Preserve the no-network content-security policy.

Use Node's built-in tests; no cloud credentials are needed in CI. Test unsafe inputs, platform differences, absent data, permission denial, exact measured thresholds and active cleanup ownership. A mocked test does not replace explicitly authorized compatibility tests against a live cluster.

## Diagnosis strategies

The [diagnosis engine](src/diagnosis/engine.mjs) owns graph-based strategy execution and reconciliation. Keep the configuration evaluator behind its explicit adapter. Test that unselected strategies are never invoked and that analysis selection cannot broaden collection consent.

Every graph edge needs existing endpoints and explicit provenance. Do not infer external group membership, effective Azure grants from friendly role names, initial compromise from public exposure, or workload identity from enablement flags alone. Preserve graph conflicts and scope gaps.

Risk and confidence are independent project-defined values. Missing/refuted risk is null, not healthy zero. Validation receipts must match the actual semantic condition and exact identity/target/context/namespace/time; canary results must never validate production attack paths. Test named-resource constraints, exclusion patterns, duplicate/mismatched subjects, stale proofs, expiry during setup, cleanup after expiry, all size/path bounds and portable-dataset path/hash checks.

The [diagnosis report](src/diagnosis/report.mjs) is separate from the classic report. Its browser filters do not execute strategies. Keep script embedding escaped, render metadata as text, use only Clawpilot colors and preserve no-network CSP. Bound large graph display with visible shown/total counts while retaining the complete exported model.

The parameterized audit also needs tests for tenant/subscription mismatches before inventory, invoker approval and strategy exclusions, multi-target output persistence, dependency scope/limits, missing companion fields, null-score behavior and forged ratings. Verify exact output shapes and 1-100 endpoints, not merely that a function returned. The shared scoring runtime serves Node and the offline browser; do not duplicate its formula in a second implementation.

Keep tests independent of credentials, public networks, current cloud configuration, fixed HTTP ports and scheduling sleeps. Preserve the caller's environment when testing per-command overrides. Rerun the full suite to look for intermittent failures and report the observed runs honestly; passing repeatedly is not a proof that flakiness is impossible. Rebuild generated samples before the full suite after catalogue changes.

Never commit real evidence, kubeconfigs, tokens, customer identifiers or credentials. Report implementation defects through your organization's approved private process when sensitive cluster details are involved.

## Wording

Describe what a command reads, measures or writes, and state its limits. Avoid slogans, promotional adjectives and claims broader than the implemented checks. Keep official product names, API identifiers, command names and referenced document titles unchanged.

## Browser acceptance

After rebuilding, open the standalone site directly from disk. Verify that getting-started instructions appear without sample metrics, the sample link opens a labelled synthetic report, and generated run reports open directly to results. Check the catalogue and command builder without a report loaded, including cloud/Local prerequisites and each launcher. Verify category/status/platform/mode/namespace filtering, scenario and WAF/area/namespace score tables, ARM-only labelling, theme switching, JSON export and valid/invalid JSON import. Invalid or score-forged imports must preserve the existing report or unloaded getting-started state. Treat long identifiers and HTML-like inventory strings as text, without horizontal overflow on a 390-pixel viewport or script execution. Check readable status-text contrast in both themes and that the document makes no external asset requests. Printing should retain evidence and source context.
