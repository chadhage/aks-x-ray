import { assess } from '../engine.mjs';
import { controls } from '../catalog.mjs';
import { validateAssessment } from '../report.mjs';
import { analyzeExposures } from './analysis.mjs';
import { armId, kubeId } from './graph.mjs';
import { makeClaim } from './reconcile.mjs';
import { targetClusterId } from '../collector.mjs';

const overlap = { 'SEC-001': 'container-privileged', 'SEC-005': 'host-namespace-sharing',
  'SEC-012': 'api-token-automount', 'CP-002': 'api-unrestricted' };
const impacts = { high: 85, medium: 60, low: 35, info: 15 };

export function evaluateConfiguration(bundles, { evaluator = assess, now }) {
  return [...bundles].sort((a, b) => (a.sources.cluster?.data?.id ?? targetClusterId(a.target)).localeCompare(b.sources.cluster?.data?.id ?? targetClusterId(b.target), 'en'))
    .map((bundle) => evaluator(bundle, { now }));
}

export function configurationClaims(graph, reports) {
  const claims = [];
  const common = analyzeExposures(graph).claims;
  for (const report of reports) {
    validateAssessment(report);
    const cluster = graph.scope.targets.find((target) => target.context === report.target.context)?.clusterId;
    if (!cluster) throw new Error('Configuration adapter target is absent from the diagnosis graph.');
    const namespacedIds = new Set(report.namespaceResults.flatMap((entry) => entry.results.map((result) => result.id)));
    const entries = [
      ...report.results.filter((result) => !namespacedIds.has(result.id)).map((result) => ({ result, namespace: null })),
      ...report.namespaceResults.flatMap((entry) => entry.results.map((result) => ({ result, namespace: entry.namespace })))
    ];
    for (const { result, namespace } of entries) {
      if (['pass', 'notApplicable'].includes(result.status)) continue;
      const control = controls.find((item) => item.id === result.id);
      const matches = result.status === 'fail' ? common.filter((claim) => claim.predicate === overlap[result.id]
        && claim.scope.clusterIds.includes(cluster) && claim.scope.namespace === namespace) : [];
      if (matches.length) {
        claims.push(...matches.map((claim) => makeClaim({ ...claim, strategy: 'configuration', controlIds: [control.id],
          baseConfidence: result.incomplete ? Math.min(35, claim.baseConfidence) : claim.baseConfidence,
          limitations: [...claim.limitations, ...(result.incomplete ? ['Configuration control has partial observations.'] : [])] })));
        continue;
      }
      const refs = graph.sources.filter((source) => source.clusterId === cluster && control.requires.includes(source.sourceId)).map((source) => source.id);
      claims.push(makeClaim({
        strategy: 'configuration', subject: namespace ? kubeId(cluster, 'Namespace', undefined, namespace) : armId(cluster),
        predicate: `configuration:${control.id}`, scope: { clusterIds: [cluster], namespace, resourceId: namespace ? null : cluster },
        title: control.title, description: result.message, stance: result.status === 'fail' ? 'supports' : 'inconclusive',
        tier: 'configured-exposure', area: control.category, baseImpact: impacts[control.severity], baseConfidence: result.incomplete ? 30 : result.status === 'fail' ? 85 : 20,
        baseFeasibility: 35, evidenceRefs: refs, validationIds: [], controlIds: [control.id],
        limitations: result.status === 'fail' ? ['A checklist deviation is not proof of exploitability.'] : ['This configuration assertion needs additional evidence.'],
        recommendation: control.remediation
      }));
    }
  }
  return { claims, gaps: [] };
}
