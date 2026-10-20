(() => {
  'use strict';
  const embedded = JSON.parse(document.getElementById('xray-data').textContent);
  const { categories, controls, sourceCatalog, catalogVersion, catalogDigest } = embedded;
  const controlById = new Map(controls.map((control) => [control.id, control]));
  const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
  const labels = { pass: 'Pass', fail: 'Fail', review: 'Review', unknown: 'Unknown', error: 'Error', notApplicable: 'Not applicable', notRun: 'Not run' };
  const modeLabels = { passive: 'Read-only', manual: 'Manual review', active: 'Opt-in active' };
  const statusOrder = ['fail', 'error', 'unknown', 'review', 'notRun', 'pass', 'notApplicable'];
  let report = embedded.assessment;
  let view = 'assessment';
  const byId = (id) => document.getElementById(id);
  const element = (tag, text, className) => {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  };
  const displayDate = (date) => new Date(date).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  const notify = (message) => {
    byId('notification').textContent = message;
    byId('notification').hidden = !message;
  };
  const badge = (text, className = '') => element('span', text, `badge ${className}`);

  function validateReport(candidate) {
    if (!candidate || candidate.schemaVersion !== '1.0' || candidate.catalogVersion !== catalogVersion || candidate.catalogDigest !== catalogDigest) {
      throw new Error('This report needs the matching schema and catalogue revision. Regenerate it with the matching AKS X-Ray version.');
    }
    if (!isObject(candidate.target) || !['cloud', 'local'].includes(candidate.target.platform)
      || typeof candidate.target.context !== 'string' || !['verified', 'unverified', 'mismatch'].includes(candidate.target.binding?.status)
      || !candidate.scope || !['production', 'development'].includes(candidate.scope.profile)
      || !Array.isArray(candidate.scope.categories) || !candidate.scope.categories.length
      || candidate.scope.categories.some((id) => !categories.some((category) => category.id === id))
      || new Set(candidate.scope.categories).size !== candidate.scope.categories.length
      || !Array.isArray(candidate.scope.excludedNamespaces)
      || !(candidate.scope.namespaces === null || Array.isArray(candidate.scope.namespaces))
      || !Number.isFinite(Date.parse(candidate.collectedAt)) || !Number.isFinite(Date.parse(candidate.assessedAt))
      || !Array.isArray(candidate.results) || candidate.results.length > controls.length) {
      throw new Error('The assessment target, scope, timestamps or result collection is invalid.');
    }
    if (typeof candidate.synthetic !== 'boolean' || typeof candidate.toolVersion !== 'string'
      || ['subscription', 'resourceGroup', 'cluster'].some((key) => typeof candidate.target[key] !== 'string' || !candidate.target[key])
      || !Array.isArray(candidate.collection) || candidate.collection.some((record) => !isObject(record)
        || typeof record.sourceId !== 'string' || !['ok', 'error', 'notCollected', 'notApplicable'].includes(record.status))
      || candidate.scope.excludedNamespaces.some((value) => typeof value !== 'string')
      || candidate.scope.namespaces?.some((value) => typeof value !== 'string')) {
      throw new Error('Invalid assessment collection provenance or namespace scope.');
    }
    if (candidate.activeRun !== undefined && (!isObject(candidate.activeRun) || !isObject(candidate.activeRun.cleanup)
      || !['pending', 'deleted', 'notFound', 'notNeeded', 'error'].includes(candidate.activeRun.cleanup.status))) {
      throw new Error('Invalid active-run cleanup provenance.');
    }
    const ids = new Set();
    for (const result of candidate.results) {
      if (!controlById.has(result.id) || !candidate.scope.categories.includes(controlById.get(result.id).category)
        || ids.has(result.id) || !Object.hasOwn(labels, result.status)
        || typeof result.message !== 'string' || typeof result.incomplete !== 'boolean'
        || !Array.isArray(result.evidence)) throw new Error('Invalid or duplicated assessment control.');
      ids.add(result.id);
    }
    const expected = controls.filter((control) => candidate.scope.categories.includes(control.category));
    if (expected.length !== ids.size || expected.some((control) => !ids.has(control.id))) throw new Error('The report omits controls from its declared category scope.');
    const count = counts(candidate);
    const applicable = candidate.results.length - count.notApplicable;
    const evaluated = count.pass + count.fail;
    const complete = candidate.results.filter((result) => ['pass', 'fail'].includes(result.status) && !result.incomplete).length;
    const summary = {
      total: candidate.results.length, applicable, evaluated, counts: count,
      partial: candidate.results.filter((result) => result.incomplete).length,
      alignmentPercent: evaluated && candidate.target.binding.status === 'verified' ? Math.round(count.pass / evaluated * 100) : null,
      evidenceCoveragePercent: applicable ? Math.round(complete / applicable * 100) : null
    };
    if (!isObject(candidate.summary) || Object.keys(candidate.summary).length !== Object.keys(summary).length
      || !isObject(candidate.summary.counts) || Object.keys(candidate.summary.counts).length !== Object.keys(labels).length
      || Object.entries(summary).some(([key, value]) => key === 'counts'
        ? Object.entries(value).some(([status, total]) => candidate.summary.counts[status] !== total)
        : candidate.summary[key] !== value)) throw new Error('The report summary does not match its findings.');
    return candidate;
  }

  function counts(candidate = report) {
    return Object.fromEntries(Object.keys(labels).map((status) => [status, candidate.results.filter((result) => result.status === status).length]));
  }

  function updateOverview() {
    const count = counts();
    const applicable = report.results.length - count.notApplicable;
    const evaluated = count.pass + count.fail;
    const complete = report.results.filter((result) => ['pass', 'fail'].includes(result.status) && !result.incomplete).length;
    const alignment = evaluated && report.target.binding.status === 'verified' ? `${Math.round(count.pass / evaluated * 100)}%` : 'N/A';
    byId('metric-fail').textContent = count.fail;
    byId('metric-alignment').textContent = alignment;
    byId('alignment-detail').textContent = `Pass ${count.pass} / ${evaluated} evaluated controls.`;
    byId('metric-coverage').textContent = applicable ? `${Math.round(complete / applicable * 100)}%` : 'N/A';
    byId('metric-unproven').textContent = count.review + count.unknown + count.error + count.notRun;
    byId('platform-label').textContent = report.target.platform === 'cloud' ? 'AKS ON AZURE' : 'AKS ON AZURE LOCAL';
    byId('context-label').textContent = report.target.context;
    byId('catalog-label').textContent = `Catalogue ${catalogVersion}`;
    byId('binding-value').textContent = report.target.binding.status;
    byId('binding-value').className = report.target.binding.status === 'verified' ? 'pass' : 'unknown';
    byId('collected-value').textContent = displayDate(report.collectedAt);
    byId('profile-value').textContent = report.scope.profile;
    byId('scope-description').textContent = `${report.scope.categories.length} categories. Namespaces: ${report.scope.namespaces?.join(', ') || 'all reachable'}; excluded: ${report.scope.excludedNamespaces.join(', ') || 'none'}. Per-source collection is not an atomic snapshot.`;
    byId('report-banner').textContent = report.synthetic
      ? 'SYNTHETIC SAMPLE - example inventory and findings for demonstration. No Azure or Kubernetes cluster was queried. Open an assessment JSON file to view collected results.'
      : 'POINT-IN-TIME ASSESSMENT - review source timestamps, collection errors, scope, and manual controls before using these results.';
    const bar = byId('status-bar');
    const legend = byId('status-legend');
    bar.replaceChildren();
    legend.replaceChildren();
    for (const [status, total] of Object.entries(count)) {
      if (!total) continue;
      const segment = element('span', undefined, `bar-${status}`);
      segment.style.width = `${total / report.results.length * 100}%`;
      bar.append(segment);
      const entry = element('span');
      entry.append(element('i', undefined, `bar-${status}`), element('span', `${labels[status]} ${total}`));
      legend.append(entry);
    }
    const operationalErrors = (report.collection || []).filter((source) => source.status === 'error');
    const cleanup = report.activeRun?.cleanup;
    const errors = [];
    if (report.target.binding.status !== 'verified') errors.push(`Target binding is ${report.target.binding.status}; cross-plane alignment is not verified.`);
    if (operationalErrors.length) errors.push(`Collection errors: ${operationalErrors.map((source) => `${source.sourceId} (${source.error?.code || 'error'})`).join(', ')}.`);
    if (cleanup?.status === 'error') errors.push(`ACTIVE CLEANUP FAILED: ${cleanup.namespace}. Use the ownership-checking recovery runbook; do not delete unrelated namespaces.`);
    if (cleanup?.status === 'pending') errors.push(`Active run is in progress or interrupted. Cleanup is not confirmed for ${report.activeRun.namespace}.`);
    byId('operational-alert').hidden = !errors.length;
    byId('operational-alert').textContent = errors.join(' ');
    const priorities = report.results.filter((result) => result.status === 'fail').sort((a, b) =>
      ['high', 'medium', 'low', 'info'].indexOf(controlById.get(a.id).severity) - ['high', 'medium', 'low', 'info'].indexOf(controlById.get(b.id).severity)).slice(0, 3);
    byId('priorities').replaceChildren(...priorities.map((result) => {
      const control = controlById.get(result.id);
      const card = element('article', undefined, 'priority-card');
      card.append(element('p', `${control.id} / ${control.severity.toUpperCase()} SEVERITY`, 'eyebrow'),
        element('h3', control.title), element('p', control.remediation));
      return card;
    }));
  }

  function sourceLink(sourceId) {
    const source = sourceCatalog.sources.find((item) => item.id === sourceId);
    const link = element('a', source.title);
    link.href = source.url;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    return link;
  }

  function findingCard(control, result) {
    const details = element('details', undefined, 'finding');
    details.id = `control-${control.id}`;
    const summary = element('summary');
    const metadata = element('div', undefined, 'finding-meta');
    metadata.append(element('span', control.id, 'control-id'), badge(control.severity, `severity-${control.severity}`),
      badge(modeLabels[control.mode]));
    const status = result ? badge(labels[result.status], `status ${result.status}`) : badge(control.platforms.join(' / '), 'status');
    summary.append(metadata, status, element('h3', control.title), element('p', result?.message || control.assertion));
    const body = element('div', undefined, 'finding-body');
    const assertion = element('section');
    assertion.append(element('h4', 'Assertion'), element('p', control.assertion));
    const remediation = element('section');
    remediation.append(element('h4', 'Suggested follow-up'), element('p', control.remediation));
    const references = element('section');
    references.append(element('h4', 'Official Microsoft guidance'));
    const links = element('ul');
    for (const id of control.sourceIds) {
      const li = element('li');
      li.append(sourceLink(id));
      links.append(li);
    }
    references.append(links);
    const boundary = element('section');
    boundary.append(element('h4', 'Scope and dependencies'), element('p',
      `Platforms: ${control.platforms.join(', ')}. Mode: ${modeLabels[control.mode]}. ${control.productionOnly ? 'Production profile only. ' : ''}Dependencies: ${control.requires.join(', ') || 'independent operational evidence'}.`));
    body.append(assertion, remediation, references, boundary);
    if (result) {
      const observed = element('section', undefined, 'observation');
      observed.append(element('h4', 'Observed evidence and collection provenance'));
      if (result.classification) observed.append(element('p', `Classification: ${result.classification}${result.incomplete ? ' | Partial evidence: unresolved observations remain.' : ''}`));
      const text = JSON.stringify({ observed: result.observed ?? null, evidence: result.evidence }, null, 2);
      observed.append(element('pre', text));
      observed.append(element('p', 'JSON pointers refer to the paired evidence.json. Commands show collection intent; timestamps delimit the observation.', 'evidence-reference'));
      body.append(observed);
    }
    details.append(summary, body);
    return details;
  }

  function updateFindings() {
    const search = byId('search').value.toLowerCase().trim();
    const category = byId('category-filter').value;
    const status = byId('status-filter').value;
    const platform = byId('platform-filter').value;
    const mode = byId('mode-filter').value;
    const results = new Map(report.results.map((result) => [result.id, result]));
    const available = view === 'catalog' ? controls : controls.filter((control) => results.has(control.id));
    const filtered = available.filter((control) => {
      const result = view === 'catalog' ? undefined : results.get(control.id);
      return (category === 'all' || control.category === category)
        && (view === 'catalog' || status === 'all' || result.status === status)
        && (view !== 'catalog' || platform === 'all' || control.platforms.includes(platform))
        && (mode === 'all' || control.mode === mode)
        && (!search || `${control.id} ${control.title} ${control.category} ${control.assertion} ${control.remediation} ${result?.message || ''}`.toLowerCase().includes(search));
    });
    if (view !== 'catalog') filtered.sort((a, b) => statusOrder.indexOf(results.get(a.id).status) - statusOrder.indexOf(results.get(b.id).status));
    byId('findings').replaceChildren(...filtered.map((control) => findingCard(control, view === 'catalog' ? undefined : results.get(control.id))));
    byId('result-count').textContent = `${filtered.length} of ${available.length} controls`;
    byId('empty-state').hidden = filtered.length > 0;
    byId('results-title').textContent = view === 'catalog' ? 'Assessment control catalogue' : 'Findings and open reviews';
    byId('results-eyebrow').textContent = view === 'catalog' ? 'ASSESSMENT CONTROLS' : 'EVIDENCE REGISTER';
  }

  function switchView(next) {
    view = next;
    for (const button of document.querySelectorAll('[data-view]')) button.setAttribute('aria-pressed', String(button.dataset.view === view));
    byId('assessment-view').hidden = view !== 'assessment';
    byId('catalog-intro').hidden = view !== 'catalog';
    byId('method-view').hidden = view !== 'method';
    byId('results-section').hidden = view === 'method';
    byId('status-filter-label').hidden = view === 'catalog';
    byId('platform-filter-label').hidden = view !== 'catalog';
    updateFindings();
  }

  function planner() {
    const launcher = byId('planner-launcher').value;
    const command = launcher === 'powershell' ? '.\\scripts\\Invoke-AksXRay.ps1' : launcher === 'bash' ? 'bash scripts/aks-xray.sh' : 'node bin/aks-xray.mjs';
    const category = byId('planner-category').value;
    byId('planned-command').textContent = `${command} collect --platform ${byId('planner-platform').value} --context "<context>" --subscription "<subscription-guid>" --resource-group "<resource-group>" --cluster "<cluster-name>"${category === 'all' ? '' : ` --categories ${category}`}`;
  }

  for (const category of categories) {
    for (const id of ['category-filter', 'planner-category']) {
      const option = element('option', category.title);
      option.value = category.id;
      byId(id).append(option);
    }
  }
  for (const [status, label] of Object.entries(labels)) {
    const option = element('option', label);
    option.value = status;
    byId('status-filter').append(option);
  }
  byId('sources').replaceChildren(...sourceCatalog.sources.map((source) => {
    const card = element('article', undefined, 'source-card');
    card.append(element('h3', source.title), element('p', source.scope), sourceLink(source.id));
    return card;
  }));
  byId('source-policy').textContent = sourceCatalog.policy;
  byId('review-date').textContent = `Guidance reviewed ${sourceCatalog.reviewedAt}`;

  for (const button of document.querySelectorAll('[data-view]')) button.addEventListener('click', () => switchView(button.dataset.view));
  for (const id of ['search', 'category-filter', 'status-filter', 'platform-filter', 'mode-filter']) byId(id).addEventListener('input', updateFindings);
  for (const id of ['planner-platform', 'planner-category', 'planner-launcher']) byId(id).addEventListener('change', planner);
  byId('reset-filters').addEventListener('click', () => {
    byId('search').value = '';
    for (const id of ['category-filter', 'status-filter', 'platform-filter', 'mode-filter']) byId(id).value = 'all';
    updateFindings();
  });
  byId('toggle-theme').addEventListener('click', () => {
    document.documentElement.setAttribute('data-theme', document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
  });
  byId('copy-command').addEventListener('click', async () => {
    try {
      if (!navigator.clipboard) throw new Error('Clipboard access is unavailable for this local file.');
      await navigator.clipboard.writeText(byId('planned-command').textContent);
      notify('Command copied. Replace placeholders locally before running it.');
    } catch (error) { notify(`Could not copy: ${error.message} Select and copy the displayed command instead.`); }
  });
  byId('import-file').addEventListener('change', async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    try {
      if (file.size > 20 * 1024 * 1024) throw new Error('The report exceeds the 20 MiB import limit.');
      const imported = validateReport(JSON.parse(await file.text()));
      report = imported;
      updateOverview();
      switchView('assessment');
      notify(`Loaded ${file.name}. This browser only reads local report data; it does not connect to your cluster.`);
    } catch (error) { notify(`Assessment was not loaded: ${error.message}`); }
    event.target.value = '';
  });
  byId('export-json').addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = element('a');
    link.href = url;
    link.download = 'assessment.json';
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  let printState;
  window.addEventListener('beforeprint', () => {
    printState = { theme: document.documentElement.getAttribute('data-theme'),
      details: [...document.querySelectorAll('.finding')].map((detail) => ({ detail, open: detail.open })) };
    document.documentElement.setAttribute('data-theme', 'light');
    for (const { detail } of printState.details) detail.open = true;
  });
  window.addEventListener('afterprint', () => {
    if (!printState) return;
    document.documentElement.setAttribute('data-theme', printState.theme);
    for (const { detail, open } of printState.details) detail.open = open;
    printState = undefined;
  });
  byId('print-report').addEventListener('click', () => window.print());
  validateReport(report);
  updateOverview();
  updateFindings();
  planner();
})();
