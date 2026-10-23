(() => {
  'use strict';
  const report = JSON.parse(document.getElementById('diagnosis-data').textContent);
  const nodes = new Map(report.graph.nodes.map((node) => [node.id, node]));
  const byId = (id) => document.getElementById(id);
  const element = (tag, text, className) => {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  };
  const badge = (text) => element('span', text, 'badge');
  const score = (value) => value === null ? 'Unscored' : `${value}/100`;
  function table(id, headings, rows) {
    const value = element('table');
    const head = element('thead');
    const header = element('tr');
    for (const title of headings) header.append(element('th', title));
    head.append(header);
    const body = element('tbody');
    for (const cells of rows) {
      const row = element('tr');
      for (const cell of cells) row.append(element('td', cell));
      body.append(row);
    }
    value.append(head, body);
    byId(id).replaceChildren(rows.length ? value : element('p', 'No observations in this selected view. Absence is not proof of security.'));
  }
  byId('diagnosis-banner').textContent = report.synthetic
    ? 'SYNTHETIC DIAGNOSIS. All metadata, attack hypotheses and validation receipts are examples. No live resources were assessed or tested.'
    : 'COLLECTED EVIDENCE. Review exact scope, timestamps, permission denials, assumptions and validation receipts. This is not an exhaustive attack-path or vulnerability assessment.';
  byId('diagnosis-scope').textContent = `Strategies: ${report.selection.strategies.join(', ')}. Approved subscriptions: ${report.graph.scope.subscriptions.length}. Targets: ${report.graph.scope.clusters.length}. Assessed: ${report.assessedAt}.`;
  byId('diagnosis-risk').textContent = score(report.summary.highestRisk);
  byId('diagnosis-findings').textContent = report.summary.total;
  byId('diagnosis-conflicts').textContent = `${report.summary.conflicting} conflicts; ${report.summary.inconclusive} inconclusive; ${report.summary.refuted} refuted.`;
  byId('diagnosis-coverage').textContent = `${report.coverage.sources.available}/${report.coverage.sources.total}`;
  byId('diagnosis-gaps').textContent = report.gaps.length;
  byId('scenario-name').textContent = report.scenario.name;
  byId('scenario-description').textContent = `Business criticality: ${report.scenario.businessCriticality}. Data sensitivity: ${report.scenario.dataSensitivity}. Intended application exposure: ${report.scenario.applicationExposure}. Risk priority and confidence are independent.`;
  byId('scenario-assumptions').textContent = `Explicit assumed-compromise nodes: ${report.scenario.assumedCompromise.join(', ') || 'none; initial access remains unknown'}.`;
  for (const strategy of report.selection.strategies) {
    const option = element('option', strategy); option.value = strategy; byId('strategy-filter').append(option);
  }
  function findings() {
    const query = byId('diagnosis-search').value.toLowerCase().trim();
    const strategy = byId('strategy-filter').value;
    const tier = byId('evidence-tier-filter').value;
    const status = byId('diagnosis-status').value;
    const selected = report.findings.filter((finding) => (strategy === 'all' || finding.strategies.includes(strategy))
      && (tier === 'all' || finding.evidenceTier === tier) && (status === 'all' || finding.status === status)
      && (!query || `${finding.title} ${finding.description} ${finding.subject} ${finding.scope.namespace ?? ''}`.toLowerCase().includes(query)));
    byId('diagnosis-result-count').textContent = `${selected.length} of ${report.findings.length} reconciled findings`;
    byId('diagnosis-finding-list').replaceChildren(...selected.map((finding) => {
      const card = element('article', undefined, `diagnosis-card ${finding.status}`);
      const metadata = element('div', undefined, 'finding-meta');
      metadata.append(badge(finding.status), badge(finding.evidenceTier), badge(`Risk ${score(finding.risk.score)}`),
        badge(`Confidence ${finding.confidence.score}/100`), badge(finding.strategies.join(' + ')));
      card.append(metadata, element('h3', finding.title), element('p', finding.description),
        element('p', `Subject: ${nodes.get(finding.subject)?.name ?? finding.subject}. Namespace: ${finding.scope.namespace ?? 'global / Azure resource'}.`, 'fine-print'),
        element('p', `Next action: ${finding.recommendation}`));
      const details = element('details');
      details.append(element('summary', 'Evidence, assumptions and strategy reconciliation'), element('pre', JSON.stringify({
        subject: finding.subject, scope: finding.scope, risk: finding.risk, confidence: finding.confidence,
        evidenceRefs: finding.evidenceRefs, validationIds: finding.validationIds, contributions: finding.contributions
      }, null, 2)));
      card.append(details);
      return card;
    }));
  }
  for (const id of ['diagnosis-search', 'strategy-filter', 'evidence-tier-filter', 'diagnosis-status']) byId(id).addEventListener('input', findings);
  byId('diagnosis-path-list').replaceChildren(...report.findings.filter((finding) => finding.paths.length).map((finding) => {
    const card = element('article', undefined, `diagnosis-card ${finding.status}`);
    card.append(element('h3', finding.title), element('p', `${finding.evidenceTier}. ${finding.description}`));
    for (const path of finding.paths) {
      const steps = element('ol', undefined, 'diagnosis-path-steps');
      for (const id of path.nodes) steps.append(element('li', `${nodes.get(id)?.name ?? id} (${nodes.get(id)?.kind ?? 'reference'})`));
      card.append(steps);
      const requirements = element('ul');
      for (const prerequisite of path.prerequisites) requirements.append(element('li', `${prerequisite.id}: ${prerequisite.status}. ${prerequisite.description}`));
      card.append(requirements);
    }
    return card;
  }));
  byId('graph-counts').textContent = `${report.graph.nodes.length} nodes, ${report.graph.edges.length} evidence-linked edges. Select a node to inspect its actual relationships; no network access occurs.`;
  for (const kind of [...new Set(report.graph.nodes.map((node) => node.kind))].sort()) {
    const option = element('option', kind); option.value = kind; byId('graph-kind').append(option);
  }
  function svgElement(tag, attributes = {}, text) {
    const value = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (const [key, attribute] of Object.entries(attributes)) value.setAttribute(key, String(attribute));
    if (text !== undefined) value.textContent = text;
    return value;
  }
  function selectNode(id) {
    const node = nodes.get(id);
    byId('graph-selected').textContent = `${node.name} (${node.kind})`;
    byId('graph-node-facts').textContent = JSON.stringify(node, null, 2);
    const relations = report.graph.edges.filter((edge) => edge.from === id || edge.to === id);
    table('graph-relations', ['From', 'Relationship', 'To', 'Evidence state'], relations.slice(0, 100).map((edge) => [
      nodes.get(edge.from)?.name ?? edge.from, edge.relationship, nodes.get(edge.to)?.name ?? edge.to, edge.state
    ]));
    const shown = relations.slice(0, 30);
    const height = Math.max(200, shown.length * 54 + 50);
    const svg = svgElement('svg', { viewBox: `0 0 1000 ${height}`, role: 'img', 'aria-label': 'Selected resource and identity relationships' });
    const center = { x: 400, y: height / 2 - 20 };
    for (const [index, edge] of shown.entries()) {
      const incoming = edge.to === id;
      const other = nodes.get(incoming ? edge.from : edge.to);
      const x = incoming ? 10 : 790;
      const y = index * 54 + 20;
      svg.append(svgElement('line', { x1: incoming ? x + 200 : center.x + 200, y1: incoming ? y + 20 : center.y + 20,
        x2: incoming ? center.x : x, y2: incoming ? center.y + 20 : y + 20, class: 'graph-link' }));
      const group = svgElement('g', { class: 'graph-node' });
      group.append(svgElement('rect', { x, y, width: 200, height: 40, rx: 8 }),
        svgElement('text', { x: x + 8, y: y + 24 }, (other?.name ?? 'reference').slice(0, 28)),
        svgElement('title', {}, `${other?.id ?? ''}; ${edge.relationship}; ${edge.state}`));
      svg.append(group, svgElement('text', { x: incoming ? 230 : 620, y: y + 15, class: 'graph-relation-label' }, edge.relationship));
    }
    const selected = svgElement('g', { class: 'graph-node selected' });
    selected.append(svgElement('rect', { ...center, width: 200, height: 40, rx: 8 }),
      svgElement('text', { x: center.x + 8, y: center.y + 24 }, node.name.slice(0, 28)), svgElement('title', {}, node.id));
    svg.append(selected);
    byId('graph-neighborhood').replaceChildren(svg, element('p',
      `Showing ${shown.length} of ${relations.length} relationships graphically and up to 100 in the table. The exported graph retains every relationship.`, 'fine-print'));
    for (const button of byId('graph-node-list').querySelectorAll('button')) button.setAttribute('aria-pressed', String(button.dataset.node === id));
  }
  function graphNodes() {
    const query = byId('graph-search').value.toLowerCase().trim();
    const kind = byId('graph-kind').value;
    const selected = report.graph.nodes.filter((node) => (kind === 'all' || node.kind === kind)
      && (!query || `${node.name} ${node.id} ${node.namespace ?? ''}`.toLowerCase().includes(query)));
    byId('graph-visible-count').textContent = `Showing ${Math.min(200, selected.length)} of ${selected.length} matching nodes. Search to narrow large graphs; exports retain all nodes.`;
    byId('graph-node-list').replaceChildren(...selected.slice(0, 200).map((node) => {
      const button = element('button', `${node.name} | ${node.kind}`);
      button.type = 'button'; button.dataset.node = node.id; button.setAttribute('aria-pressed', 'false');
      button.addEventListener('click', () => selectNode(node.id));
      return button;
    }));
  }
  for (const id of ['graph-search', 'graph-kind']) byId(id).addEventListener('input', graphNodes);
  table('diagnosis-plan-table', ['Stage', 'Test', 'Context', 'Scope', 'State', 'Permission', 'Reason'], report.plan.actions.map((action) =>
    [action.stage, action.testId, action.context, action.ownedNamespace ?? action.namespace ?? 'cluster / owned namespace', action.status, action.permissionStatus, action.reasons.join(' ')]));
  byId('diagnosis-validation-records').textContent = JSON.stringify(report.validationRecords, null, 2);
  for (const [id, views] of [['diagnosis-namespace-table', report.views.namespaces], ['diagnosis-area-table', report.views.areas]]) {
    table(id, ['View', 'Findings', 'Highest risk', 'Conflicts'], views.map((view) => [view.id, view.findingIds.length, score(view.highestRisk), view.conflicts]));
  }
  table('diagnosis-configuration-table', ['Target', 'Legacy adherence (higher is better)', 'Evidence coverage', 'Controls'], report.configurationAssessments.map((assessment) =>
    [assessment.target.cluster, score(assessment.ratings.overall.score), `${assessment.summary.evidenceCoveragePercent ?? 'unavailable'}%`, assessment.results.length]));
  byId('diagnosis-gap-list').replaceChildren(...report.gaps.map((gap) =>
    element('div', `${gap.code}: ${gap.reason ?? gap.subject ?? gap.sourceId ?? 'See structured evidence.'}`, 'diagnosis-gap')));
  byId('diagnosis-methodology').textContent = `${report.methodology.risk} ${report.methodology.confidence} ${report.methodology.scope}`;
  byId('diagnosis-source-records').textContent = JSON.stringify(report.graph.sources, null, 2);
  byId('diagnosis-theme').addEventListener('click', () => document.documentElement.setAttribute('data-theme',
    document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark'));
  byId('print-diagnosis').addEventListener('click', () => window.print());
  byId('export-diagnosis').addEventListener('click', () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
    const link = element('a'); link.href = url; link.download = 'diagnosis.json'; document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  findings();
  graphNodes();
  const first = report.graph.nodes.find((node) => node.kind === 'azure-principal') ?? report.graph.nodes[0];
  if (first) selectNode(first.id);
})();
