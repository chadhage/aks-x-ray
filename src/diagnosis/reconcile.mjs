import { canonical, kubeId, stableId } from './graph.mjs';
import { assessmentStrategies, evidenceTiers } from './strategies.mjs';
import { isGuid, normalizeRiskScenario } from '../scope.mjs';
import { loadStatistics } from '../rules.mjs';

const unique = (values) => [...new Set(values)].sort();
const clamp = (value, minimum = 1, maximum = 100) => Math.max(minimum, Math.min(maximum, value));
const permissionPredicates = { 'list::secrets': 'can-list-secrets', 'create::pods': 'can-create-pods', 'create::pods/exec': 'can-exec-pods' };
export function authenticatedSubjectId(cluster, username) {
  const account = /^system:serviceaccount:([^:]+):([^:]+)$/.exec(username);
  return account ? kubeId(cluster, 'ServiceAccount', account[1], account[2]) : kubeId(cluster, 'Identity-User', undefined, username);
}

export function makeClaim(input) {
  if (!assessmentStrategies.includes(input.strategy)) throw new Error('Unsupported assessment strategy claim.');
  for (const key of ['subject', 'predicate', 'title', 'description', 'area']) if (typeof input[key] !== 'string' || !input[key].length) throw new Error(`Claim ${key} is required.`);
  if (!['supports', 'refutes', 'inconclusive'].includes(input.stance) || !evidenceTiers.includes(input.tier)) throw new Error('Invalid claim stance or evidence tier.');
  if (!input.scope || !Array.isArray(input.scope.clusterIds) || input.scope.clusterIds.some((id) => typeof id !== 'string')
    || !(input.scope.namespace === null || typeof input.scope.namespace === 'string')
    || !(input.scope.resourceId === null || typeof input.scope.resourceId === 'string')) throw new Error('Claim scope is incomplete.');
  if (!Number.isFinite(input.baseConfidence) || input.baseConfidence < 1 || input.baseConfidence > 100
    || !Number.isFinite(input.baseImpact) || input.baseImpact < 1 || input.baseImpact > 100) throw new Error('Claim impact/confidence must be 1-100.');
  if (!Array.isArray(input.evidenceRefs) || input.evidenceRefs.some((id) => typeof id !== 'string')
    || input.stance !== 'inconclusive' && !input.evidenceRefs.length) throw new Error('Observed claims require evidence references.');
  const scope = { clusterIds: unique(input.scope.clusterIds.map((id) => id.toLowerCase())), namespace: input.scope.namespace,
    resourceId: input.scope.resourceId?.toLowerCase() ?? null };
  const normalized = {
    strategy: input.strategy, subject: input.subject, predicate: input.predicate, scope,
    title: input.title, description: input.description, stance: input.stance, tier: input.tier, area: input.area,
    baseImpact: input.baseImpact, baseConfidence: input.baseConfidence, baseFeasibility: input.baseFeasibility ?? 40,
    evidenceRefs: unique(input.evidenceRefs), validationIds: unique(input.validationIds ?? []),
    limitations: unique(input.limitations ?? []), recommendation: input.recommendation ?? 'Review the evidence and intended workload controls before remediation.',
    controlIds: unique(input.controlIds ?? []), ...(input.path ? { path: structuredClone(input.path) } : {})
  };
  if (!Number.isFinite(normalized.baseFeasibility) || normalized.baseFeasibility < 1 || normalized.baseFeasibility > 100) throw new Error('Invalid claim feasibility index.');
  if (normalized.path && (!Array.isArray(normalized.path.nodes) || !Array.isArray(normalized.path.edges)
    || !Array.isArray(normalized.path.prerequisites) || normalized.path.prerequisites.some((item) =>
      !['satisfied', 'assumed', 'unknown', 'blocked'].includes(item.status)))) throw new Error('Invalid attack-path prerequisites.');
  const issueKey = stableId('finding', [normalized.subject, normalized.predicate, scope.namespace, scope.resourceId ?? scope.clusterIds]);
  return { id: stableId('claim', normalized), issueKey, ...normalized };
}

export function receiptMatches(record, claim, { graph, now, maxEvidenceAgeHours }) {
  const fail = (reason) => ({ valid: false, reason });
  if (!record || record.status !== 'completed' || typeof record.value !== 'boolean') return fail('Validation did not complete with an explicit result.');
  if (record.synthetic !== graph.synthetic) return fail('Synthetic and real validation evidence cannot be mixed.');
  const age = now.getTime() - Date.parse(record.completedAt);
  if (!Number.isFinite(age) || age < -300_000 || age > maxEvidenceAgeHours * 3_600_000) return fail('Validation is stale or has an invalid timestamp.');
  if (record.subject !== claim.subject || record.predicate !== claim.predicate || record.namespace !== claim.scope.namespace
    || !claim.scope.clusterIds.includes(record.clusterId?.toLowerCase())) return fail('Validation subject, predicate, namespace or target differs.');
  if ((claim.stance === 'supports') !== record.value || claim.stance === 'inconclusive') return fail('Validation result does not support this claim stance.');
  const target = graph.scope.targets.find((item) => item.clusterId === record.clusterId?.toLowerCase() && item.context === record.context);
  if (!target || target.bindingStatus !== 'verified' || target.bindingMode === 'arm-only') return fail('Validation context lacks verified cross-plane binding.');
  if (!Array.isArray(record.commands) || !record.commands.length || record.commands.some((command) =>
    !['az', 'kubectl'].includes(command.file) || !Array.isArray(command.args)
    || command.args.some((argument) => typeof argument !== 'string' || /^--as(?:=|$|-group)/.test(argument)))) return fail('Validation command provenance is invalid.');
  const kubeCommands = record.commands.filter((command) => command.file === 'kubectl');
  if (!kubeCommands.length || kubeCommands.some((command) => {
    const index = command.args.indexOf('--context');
    return index < 0 || command.args[index + 1] !== record.context;
  })) return fail('Validation command context differs.');
  if (record.method === 'IsolatedCanary') {
    const ownership = record.ownership;
    if (record.stage !== 'intrusive' || !ownership || !isGuid(ownership.runId)
      || record.namespace !== `aks-xray-${ownership.runId.slice(0, 18)}` || !ownership.uid
      || !['deleted', 'notFound'].includes(ownership.cleanup)) return fail('Owned canary scope or cleanup is unverified.');
    const measurement = record.measurement;
    let observed;
    if (record.predicate === 'canary-connectivity-failed') observed = !(measurement?.resolved === true && measurement.httpStatus === 200 && measurement.markerMatched === true);
    else if (record.predicate === 'canary-http-failed') observed = !(measurement?.attempted === 3 && measurement.successes === 3);
    else if (record.predicate === 'canary-admits-privileged') {
      if (measurement?.dryRun !== true || typeof measurement.denied !== 'boolean' || measurement.reason !== 'restricted-pod-security') return fail('Admission canary has no specific policy result.');
      observed = !measurement.denied;
    } else if (record.predicate === 'canary-load-budget-exceeded') {
      try { observed = !loadStatistics(measurement).withinBudgets; }
      catch { return fail('Canary load measurement is invalid or out of bounds.'); }
    } else return fail('Unknown canary semantic condition.');
    return observed === record.value ? { valid: true } : fail('Canary result does not match its measurements.');
  }
  if (target.excludedNamespaces.includes(record.namespace) || target.namespaces !== null && !target.namespaces.includes(record.namespace)) {
    return fail('Validation namespace is outside the assessed scope.');
  }
  if (!record.authenticatedSubject?.username
    || authenticatedSubjectId(record.clusterId, record.authenticatedSubject.username) !== record.subject
    || record.authenticatedSubjectAfter?.username !== record.authenticatedSubject.username
    || record.authenticatedSubject.uid && record.authenticatedSubjectAfter?.uid !== record.authenticatedSubject.uid
    || !kubeCommands.some((command) => command.args.includes('auth') && command.args.includes('whoami'))) return fail('Current authenticated subject was not established.');
  if (record.method === 'SelfSubjectAccessReview' && record.testId === 'authorization-review' && record.stage === 'non-mutating') {
    const request = record.request;
    const predicate = request ? permissionPredicates[`${request.verb}:${request.group}:${request.resource}${request.subresource ? `/${request.subresource}` : ''}`] : undefined;
    if (predicate !== record.predicate || request.namespace !== record.namespace || record.response?.allowed !== record.value
      || record.response.evaluationErrorPresent !== false || record.response.denied === true && record.response.allowed === true
      || !kubeCommands.some((command) => command.args.includes('--raw=/apis/authorization.k8s.io/v1/selfsubjectaccessreviews'))) return fail('Authorization receipt cannot establish this semantic condition.');
    return { valid: true };
  }
  if (record.method === 'ServerSideDryRun' && record.testId === 'admission-dry-run' && record.stage === 'non-mutating') {
    if (record.predicate !== 'privileged-pod-admitted' || record.request?.privileged !== true
      || record.request.dryRun !== true || record.response?.accepted !== record.value
      || !record.value && !['restricted-pod-security', 'mutation-removed-privilege'].includes(record.response.denialKind)
      || !kubeCommands.some((command) => command.args.includes('create') && command.args.includes('--dry-run=server'))) return fail('Admission receipt cannot establish this semantic condition.');
    return { valid: true };
  }
  return fail('Validation method and semantic condition are not supported.');
}

export function reconcile(inputs, { graph, scenario, validations = [], now = new Date(), maxEvidenceAgeHours = 24 }) {
  const context = normalizeRiskScenario(scenario ?? {}, 'production');
  const sourceById = new Map(graph.sources.map((source) => [source.id, source]));
  const records = new Map(validations.map((record) => [record.id, record]));
  const claims = [...new Map(inputs.map(makeClaim).map((claim) => [claim.id, claim])).values()].sort((a, b) => a.id.localeCompare(b.id, 'en'));
  const grouped = new Map();
  for (const claim of claims) {
    if (claim.evidenceRefs.some((id) => !sourceById.has(id))) throw new Error('A strategy claim references unknown evidence.');
    const limitations = [...claim.limitations];
    let tier = claim.tier;
    if (claim.path) {
      if (claim.path.nodes.some((id) => !graph.nodes.some((node) => node.id === id))
        || claim.path.edges.some((id) => !graph.edges.some((edge) => edge.id === id))) throw new Error('An attack path references unknown graph elements.');
      if (claim.path.prerequisites.some((item) => ['unknown', 'blocked'].includes(item.status))) {
        tier = 'configured-exposure';
        limitations.push('Attack-path prerequisites are unresolved or blocked.');
      }
      if (claim.path.prerequisites.some((item) => item.status === 'assumed')) limitations.push('Initial compromise or another prerequisite is an explicit scenario assumption, not an observed exploit.');
    }
    if (tier === 'validated-behavior') {
      const matched = claim.validationIds.map((id) => receiptMatches(records.get(id), claim, { graph, now, maxEvidenceAgeHours }));
      if (!matched.some((item) => item.valid)) {
        tier = 'configured-exposure';
        limitations.push(`Validation is not bound to this exact conclusion: ${matched.map((item) => item.reason).join(' ') || 'no receipt supplied'}`);
      }
    }
    let confidence = claim.baseConfidence;
    if (!claim.evidenceRefs.length) { confidence = Math.min(confidence, 20); limitations.push('No observed source evidence supports this conclusion.'); }
    for (const ref of claim.evidenceRefs) {
      const source = sourceById.get(ref);
      const age = now.getTime() - Date.parse(source.collectedAt);
      if (age > maxEvidenceAgeHours * 3_600_000 || age < -300_000) { confidence = Math.min(confidence, 35); limitations.push('Source evidence is stale or has clock skew.'); }
      if (source.status !== 'ok') { confidence = Math.min(confidence, 40); limitations.push('A supporting source is partial or unavailable.'); }
      if (source.bindingStatus !== 'verified') { confidence = Math.min(confidence, 25); tier = 'configured-exposure'; limitations.push('Target correlation is unverified.'); }
    }
    if (claim.path?.prerequisites.some((item) => item.status === 'assumed')) confidence = Math.min(confidence, 70);
    const contribution = { ...claim, effectiveTier: tier, confidence: clamp(confidence), limitations: unique(limitations) };
    grouped.set(claim.issueKey, [...(grouped.get(claim.issueKey) ?? []), contribution]);
  }
  const findings = [...grouped.entries()].map(([id, contributions]) => {
    const positive = contributions.filter((claim) => claim.stance === 'supports');
    const negative = contributions.filter((claim) => claim.stance === 'refutes');
    const status = positive.length && negative.length ? 'conflicting' : positive.length ? 'observed' : negative.length ? 'refuted' : 'inconclusive';
    const primary = [...(positive.length ? positive : contributions)].sort((a, b) => b.baseImpact - a.baseImpact || a.id.localeCompare(b.id, 'en'))[0];
    const criticality = { low: 0.65, medium: 0.85, high: 1, critical: 1.2 }[context.businessCriticality];
    const sensitivity = { public: 0.75, internal: 0.9, confidential: 1.1, restricted: 1.25 }[context.dataSensitivity];
    const impact = positive.length ? clamp(Math.round(Math.max(...positive.map((claim) => claim.baseImpact)) * criticality * sensitivity)) : null;
    let feasibility = positive.length ? Math.max(...positive.map((claim) => claim.baseFeasibility)) : null;
    if (primary.predicate === 'public-entry' && feasibility !== null) feasibility = clamp(feasibility + (context.applicationExposure === 'private' ? 15 : -10));
    const risk = impact === null ? null : clamp(Math.round(impact * feasibility / 100));
    const limitations = unique(contributions.flatMap((claim) => claim.limitations));
    let confidence = Math.max(...contributions.map((claim) => claim.confidence));
    if (status === 'conflicting') { confidence = Math.min(confidence, 45); limitations.push('Conflicting claims are preserved; confidence voting and last-write-wins resolution were not applied.'); }
    const evidenceTier = [...contributions].sort((a, b) => evidenceTiers.indexOf(b.effectiveTier) - evidenceTiers.indexOf(a.effectiveTier))[0].effectiveTier;
    return {
      id, subject: primary.subject, predicate: primary.predicate, title: primary.title, description: primary.description,
      scope: { ...primary.scope, clusterIds: unique(contributions.flatMap((claim) => claim.scope.clusterIds)) }, area: primary.area,
      status, evidenceTier, strategies: unique(contributions.map((claim) => claim.strategy)), contributions,
      evidenceRefs: unique(contributions.flatMap((claim) => claim.evidenceRefs)),
      validationIds: unique(contributions.flatMap((claim) => claim.validationIds)),
      paths: [...new Map(contributions.filter((claim) => claim.path).map((claim) => [canonical(claim.path), claim.path])).values()],
      risk: { score: risk, impact, feasibilityIndex: feasibility, higherIsWorse: true,
        rationale: 'Project-defined priority from consequence, scenario and feasibility; confidence is not multiplied into risk.' },
      confidence: { score: clamp(confidence), limitations: unique(limitations) }, recommendation: primary.recommendation
    };
  }).sort((a, b) => (b.risk.score ?? -1) - (a.risk.score ?? -1) || a.id.localeCompare(b.id, 'en'));
  const highest = (items) => {
    const scores = items.map((finding) => finding.risk.score).filter((value) => value !== null);
    return scores.length ? Math.max(...scores) : null;
  };
  const groups = (keys, predicate) => unique(keys).map((id) => {
    const selected = findings.filter((finding) => predicate(finding, id));
    return { id, findingIds: selected.map((finding) => finding.id), highestRisk: highest(selected),
      conflicts: selected.filter((finding) => finding.status === 'conflicting').length };
  });
  return {
    findings,
    summary: { total: findings.length, observed: findings.filter((item) => item.status === 'observed').length,
      conflicting: findings.filter((item) => item.status === 'conflicting').length, refuted: findings.filter((item) => item.status === 'refuted').length,
      inconclusive: findings.filter((item) => item.status === 'inconclusive').length, highestRisk: highest(findings),
      assurance: 'Absence of findings is not proof of security or complete coverage.' },
    views: {
      namespaces: groups(findings.map((finding) => finding.scope.namespace).filter((value) => value && value !== '*'), (finding, id) => finding.scope.namespace === id),
      areas: groups(findings.map((finding) => finding.area), (finding, id) => finding.area === id),
      clusters: groups(findings.flatMap((finding) => finding.scope.clusterIds), (finding, id) => finding.scope.clusterIds.includes(id))
    }
  };
}
