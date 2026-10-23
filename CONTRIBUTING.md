# Contributing

## Add or change a control

1. Start from current **official Microsoft** documentation, not a third-party checklist.
2. Register the exact source URL, scope and review date in [the source registry](catalog/sources.json). Public Microsoft Learn references are currently the enforced allowlist.
3. State a narrow, testable assertion and its caveats in [the control catalogue](catalog/controls.json).
4. Declare category, platform, profile, evidence dependencies, operational severity and failure classification.
5. Use a manual review when static data cannot establish the claim. Never infer support expiration from a version comparison, backup recovery from installation, or effective policy from an enabled flag.
6. Extend an allowlisted projection/collector only when necessary. Do not add secret values, logs, arbitrary exec or mutation to passive collection.
7. Implement the evaluator, preserving unknown/partial/error behavior, and add focused positive/negative/boundary tests.
8. Update the narrowly enumerated reader role and schemas when the evidence contract changes.
9. Update directly related documentation and the catalogue version/review metadata. The digest automatically changes with catalogue contents; old evidence requires its matching revision.

## Validate

```powershell
npm run check
npm test
npm run build:site
```

The [getting-started homepage](site/index.html), [sample HTML report](site/sample.html) and synthetic JSON example are generated and committed. Do not edit them by hand; edit [the HTML template](site/template.html), [styles](site/styles.css), [browser script](site/app.js) or [demo fixture](examples/demo.mjs), then rebuild. Keep the demo timestamp fixed so builds are deterministic. The homepage must not embed an assessment; only the explicit sample link opens synthetic results.

Use only Clawpilot theme variables for component colors, local system fonts and inline dependencies. Browser imports must treat inventory as text, reject invalid report shapes and never execute source-provided HTML or URLs. Preserve the no-network content-security policy.

Use Node's built-in tests; no cloud credentials are needed in CI. Test unsafe inputs, platform differences, absent data, permission denial, exact measured thresholds and active cleanup ownership. A mocked test does not replace explicitly authorized compatibility tests against a live cluster.

Never commit real evidence, kubeconfigs, tokens, customer identifiers or credentials. Report implementation defects through your organization's approved private process when sensitive cluster details are involved.

## Wording

Describe what a command reads, measures or writes, and state its limits. Avoid slogans, promotional adjectives and claims broader than the implemented checks. Keep official product names, API identifiers, command names and referenced document titles unchanged.

## Browser acceptance

After rebuilding, open the standalone site directly from disk. Verify that getting-started instructions appear without sample metrics, the sample link opens a labelled synthetic report, and generated run reports open directly to results. Check the catalogue and command builder without a report loaded, including cloud/Local prerequisites and each launcher. Verify category/status/platform/mode filtering, theme switching, JSON export and valid/invalid JSON import. Invalid imports must preserve the existing report or unloaded getting-started state. Treat long identifiers and HTML-like inventory strings as text, without horizontal overflow on a 390-pixel viewport or script execution. Check readable status-text contrast in both themes and that the document makes no external asset requests. Printing should retain evidence and source context.
