import { createHash, randomUUID } from 'node:crypto';
import { runActive, startPortForward } from '../active.mjs';
import { sourceCatalog } from '../catalog.mjs';
import { targetClusterId } from '../collector.mjs';
import { projectSource } from '../projection.mjs';
import { commandFailure, CommandError, parseCommandJson, runCommand } from '../process.mjs';
import { isGuid, verifySubscriptions } from '../scope.mjs';
import { canonical, GraphLimitError, kubeId, stableId } from './graph.mjs';
import { authenticatedSubjectId, makeClaim, receiptMatches } from './reconcile.mjs';
import { approvalReasons, intrusiveRequirements, planAssessment } from './planner.mjs';

const reviewRequests = (namespace) => [
  { predicate: 'can-list-secrets', group: '', resource: 'secrets', verb: 'list', namespace },
  { predicate: 'can-create-pods', group: '', resource: 'pods', verb: 'create', namespace },
  { predicate: 'can-exec-pods', group: '', resource: 'pods', subresource: 'exec', verb: 'create', namespace }
];
const suiteResults = {
  connectivity: ['activeConnectivity', 'canary-connectivity-failed'],
  'end-to-end': ['activeE2E', 'canary-http-failed'],
  load: ['activeLoad', 'canary-load-budget-exceeded'],
  security: ['activeSecurity', 'canary-admits-privileged']
};

export async function executeValidationStages(inputs, assessment, {
  runner = runCommand, now = () => new Date(), signal, runIdFactory = randomUUID,
  intrusiveRunner = runActive, persist = async () => {}, progress = () => {}
} = {}) {
  const bundles = structuredClone(inputs);
  const records = [];
  const prepared = new Map();
  let used = 0;
  let stopped = false;
  const initial = planAssessment(bundles, assessment, { now: now() });
  const evidenceFor = (action) => bundles.find((bundle) => (bundle.sources.cluster?.data?.id ?? targetClusterId(bundle.target)).toLowerCase() === action.clusterId && bundle.target.context === action.context);
  const baseRecord = (action, extra = {}) => ({
    id: stableId('validation', [action.id, extra.predicate ?? null, now().toISOString(), records.length]),
    actionId: action.id, testId: action.testId, stage: action.stage, clusterId: action.clusterId,
    context: action.context, namespace: action.namespace, synthetic: evidenceFor(action).synthetic,
    startedAt: now().toISOString(), completedAt: now().toISOString(), ...extra
  });
  const invoke = async (commands, file, args, options = {}) => {
    if (signal?.aborted) throw new CommandError('ABORTED', 'Validation was cancelled.');
    const command = { file, args };
    commands.push(command);
    return runner(file, args, { signal, ...options });
  };
  const kube = (action, commands, args, options) => invoke(commands, 'kubectl',
    ['--context', action.context, '--request-timeout=20s', ...args], options);
  const whoami = async (action, commands) => {
    const response = parseCommandJson((await kube(action, commands, ['auth', 'whoami', '--output=json'])).stdout);
    const user = response.status?.userInfo;
    if (response.kind !== 'SelfSubjectReview' || typeof user?.username !== 'string' || !user.username) throw new CommandError('INVALID_IDENTITY', 'The server did not return an authenticated self-subject identity.');
    return { username: user.username, ...(typeof user.uid === 'string' ? { uid: user.uid } : {}),
      groups: Array.isArray(user.groups) ? user.groups.filter((group) => typeof group === 'string') : [] };
  };
  const prepareTarget = async (action, commands) => {
    const evidence = evidenceFor(action);
    if (evidence.target.tenant) await verifySubscriptions({ tenant: evidence.target.tenant, subscriptions: evidence.scope.authorizedSubscriptions }, {
      runner: (file, args) => invoke(commands, file, args)
    });
    const response = await kube(action, commands, ['config', 'view', '--minify', '--output=jsonpath={.clusters[0].cluster.server}']);
    if (projectSource('context', response.stdout).server !== evidence.sources.context?.data?.server) throw new CommandError('TARGET_CHANGED', 'The explicit context endpoint changed; recollect before validation.');
    return whoami(action, commands);
  };
  const checkBudget = () => {
    if (used >= assessment.maxValidationChecks) throw new CommandError('VALIDATION_LIMIT', 'Validation check limit reached; remaining checks were not executed.');
    used++;
  };
  const review = async (action, commands, request, actor) => {
    checkBudget();
    const { predicate, ...attributes } = request;
    const resourceAttributes = Object.fromEntries(Object.entries(attributes).filter(([, value]) => value !== null));
    const payload = { apiVersion: 'authorization.k8s.io/v1', kind: 'SelfSubjectAccessReview', spec: { resourceAttributes } };
    const result = parseCommandJson((await kube(action, commands,
      ['create', '--raw=/apis/authorization.k8s.io/v1/selfsubjectaccessreviews', '--filename=-'], { input: JSON.stringify(payload) })).stdout);
    if (result.kind !== 'SelfSubjectAccessReview' || typeof result.status?.allowed !== 'boolean'
      || result.status.allowed && result.status.denied || result.status.evaluationError) throw new CommandError('INVALID_REVIEW', 'Authorization review was incomplete or malformed; no permission conclusion was made.');
    const after = await whoami(action, commands);
    if (after.username !== actor.username || actor.uid && after.uid !== actor.uid) throw new CommandError('SUBJECT_CHANGED', 'The authenticated subject changed during validation.');
    return { request: attributes, allowed: result.status.allowed, denied: result.status.denied === true,
      evaluationErrorPresent: false, authenticatedSubjectAfter: after, predicate };
  };
  const currentReasons = (action, namespace) => {
    const evidence = evidenceFor(action);
    return approvalReasons(assessment.approvals[action.stage === 'intrusive' ? 'intrusive' : 'nonMutating'],
      { evidence, context: action.context }, now(), namespace);
  };
  const failRecord = (action, error, commands, extra = {}) => {
    const failure = commandFailure(error);
    const status = ['VALIDATION_LIMIT', 'ABORTED', 'PERMISSION_DENIED', 'APPROVAL_EXPIRED'].includes(failure.code) ? 'blocked' : 'error';
    const record = baseRecord(action, { ...extra, status, error: failure, reason: failure.message, commands: structuredClone(commands) });
    records.push(record);
    progress(`Validation ${status} [${action.testId}]: ${failure.code}: ${failure.message}`);
    if (['SUBJECT_CHANGED', 'TARGET_CHANGED', 'ABORTED'].includes(failure.code)) stopped = true;
  };
  for (const action of initial.actions.filter((item) => item.stage === 'non-mutating')) {
    const namespace = action.testId === 'intrusive-preflight' ? undefined : action.namespace ?? undefined;
    const reasons = [...action.reasons, ...currentReasons(action, namespace)];
    if (stopped || reasons.length || action.status === 'blocked') {
      records.push(baseRecord(action, { status: 'blocked', reason: stopped ? 'A previous identity/target/cancellation stop condition prevents validation.' : reasons.join(' '), commands: [] }));
      continue;
    }
    const commands = [];
    try {
      const actor = await prepareTarget(action, commands);
      const subject = authenticatedSubjectId(action.clusterId, actor.username);
      if (action.testId === 'intrusive-preflight') {
        const runId = runIdFactory();
        if (!isGuid(runId)) throw new CommandError('INVALID_RUN_ID', 'Prepared canary run ID is invalid.');
        const ownedNamespace = `aks-xray-${runId.slice(0, 18)}`;
        const checks = [];
        for (const request of intrusiveRequirements(action.suite, ownedNamespace)) {
          if (currentReasons(action).length) throw new CommandError('APPROVAL_EXPIRED', 'Approval expired during permission preflight.');
          checks.push(await review(action, commands, request, actor));
        }
        const record = baseRecord(action, { status: 'completed', testId: 'intrusive-preflight', forActionId: action.forActionId,
          namespace: ownedNamespace, runId, subject, authenticatedSubject: actor, checks, commands: structuredClone(commands) });
        records.push(record);
        prepared.set(action.forActionId, record);
      } else if (action.testId === 'authorization-review') {
        for (const request of reviewRequests(action.namespace)) {
          if (stopped) { records.push(baseRecord(action, { status: 'blocked', predicate: request.predicate, reason: 'Authenticated subject changed; remaining reviews were stopped.', commands: [] })); continue; }
          try {
            if (currentReasons(action, action.namespace).length) throw new CommandError('APPROVAL_EXPIRED', 'Approval expired before the next authorization review.');
            const outcome = await review(action, commands, request, actor);
            records.push(baseRecord(action, { status: 'completed', method: 'SelfSubjectAccessReview', predicate: request.predicate,
              value: outcome.allowed, subject, authenticatedSubject: actor, authenticatedSubjectAfter: outcome.authenticatedSubjectAfter,
              request: outcome.request, response: { allowed: outcome.allowed, denied: outcome.denied, evaluationErrorPresent: false },
              commands: structuredClone(commands) }));
          } catch (error) { failRecord(action, error, commands, { predicate: request.predicate }); }
        }
      } else if (action.testId === 'admission-dry-run') {
        const permission = await review(action, commands, { group: '', resource: 'pods', verb: 'create', namespace: action.namespace }, actor);
        if (!permission.allowed) throw new CommandError('PERMISSION_DENIED', 'Pod-create permission was denied; no admission probe was submitted.');
        if (currentReasons(action, action.namespace).length) throw new CommandError('APPROVAL_EXPIRED', 'Approval expired before the admission dry-run.');
        checkBudget();
        const name = `aks-xray-negative-${stableId('probe', [action.id, now().toISOString()]).split(':')[1].slice(0, 10)}`;
        const pod = { apiVersion: 'v1', kind: 'Pod', metadata: { name, namespace: action.namespace },
          spec: { automountServiceAccountToken: false, restartPolicy: 'Never', containers: [{
            name: 'negative', image: sourceCatalog.activeImage.reference, securityContext: { privileged: true },
            resources: { requests: { cpu: '10m', memory: '32Mi' }, limits: { cpu: '100m', memory: '64Mi' } }
          }] } };
        let accepted;
        let denialKind;
        try {
          const response = parseCommandJson((await kube(action, commands, ['create', '--dry-run=server', '--filename=-', '--output=json'],
            { input: JSON.stringify(pod) })).stdout);
          if (response.kind !== 'Pod' || !Array.isArray(response.spec?.containers)) throw new CommandError('INVALID_ADMISSION', 'Server-side dry-run did not return a Pod.');
          accepted = response.spec.containers.some((container) => container.securityContext?.privileged === true);
          if (!accepted) denialKind = 'mutation-removed-privilege';
        } catch (error) {
          if (!(error instanceof CommandError) || !/violates PodSecurity ["']restricted(?::[^"']+)?["']/i.test(error.stderr)) throw error;
          accepted = false;
          denialKind = 'restricted-pod-security';
        }
        const after = await whoami(action, commands);
        if (after.username !== actor.username || actor.uid && after.uid !== actor.uid) throw new CommandError('SUBJECT_CHANGED', 'The authenticated subject changed during validation.');
        records.push(baseRecord(action, { status: 'completed', method: 'ServerSideDryRun', predicate: 'privileged-pod-admitted',
          value: accepted, subject, authenticatedSubject: actor, authenticatedSubjectAfter: after,
          request: { privileged: true, dryRun: true, name, namespace: action.namespace },
          response: { accepted, ...(denialKind ? { denialKind } : {}) }, commands: structuredClone(commands) }));
      }
    } catch (error) { failRecord(action, error, commands); }
  }
  for (const original of initial.actions.filter((item) => item.stage === 'intrusive')) {
    const action = planAssessment(bundles, assessment, { now: now(), records }).actions.find((item) => item.id === original.id);
    const preflight = prepared.get(action.id);
    if (stopped || action.status !== 'ready' || !preflight) {
      records.push(baseRecord(action, { status: 'blocked', reason: stopped ? 'Previous validation failure/cleanup stop condition.' : action.reasons.join(' '), commands: [] }));
      continue;
    }
    const commands = [];
    try {
      const actor = await prepareTarget(action, commands);
      if (actor.username !== preflight.authenticatedSubject.username
        || preflight.authenticatedSubject.uid && actor.uid !== preflight.authenticatedSubject.uid) throw new CommandError('SUBJECT_CHANGED', 'Authenticated subject differs from the permission preflight.');
      if (currentReasons(action).length) throw new CommandError('APPROVAL_EXPIRED', 'Intrusive approval expired immediately before mutation.');
      const evidence = evidenceFor(action);
      const stageAbort = new AbortController();
      const cancel = () => stageAbort.abort(signal?.reason);
      signal?.addEventListener('abort', cancel, { once: true });
      if (signal?.aborted) cancel();
      const expiresIn = Date.parse(assessment.approvals.intrusive.expiresAt) - now().getTime();
      const expiry = setTimeout(() => stageAbort.abort(new Error('Intrusive approval expired.')), Math.min(Math.max(1, expiresIn), 2_147_483_647));
      const guard = () => {
        if (currentReasons(action).length) throw new CommandError('APPROVAL_EXPIRED', 'Intrusive approval expired; new test activity is blocked. Owned cleanup remains permitted.');
        if (stageAbort.signal.aborted) throw new CommandError('ABORTED', 'Intrusive activity was cancelled.');
      };
      const guardedRunner = (file, args, options = {}) => {
        if (file === 'az') {
          if (args[0] !== 'account' || args[1] !== 'show') throw new CommandError('SCOPE_DENIED', 'The canary runner cannot mutate Azure resources.');
          return runner(file, args, options);
        }
        if (file !== 'kubectl' || args[args.indexOf('--context') + 1] !== action.context) throw new CommandError('SCOPE_DENIED', 'Canary command context differs from its approval.');
        const cleanup = (args.includes('get') || args.includes('delete')) && args.includes('namespace')
          && args[args.indexOf('namespace') + 1] === preflight.namespace;
        if (!cleanup) {
          guard();
          if (args.includes('create')) {
            const payload = parseCommandJson(options.input);
            if (payload.kind === 'Namespace' ? payload.metadata?.name !== preflight.namespace
              : payload.kind === 'List' ? !Array.isArray(payload.items) || payload.items.some((item) =>
                !['ResourceQuota', 'NetworkPolicy', 'Service', 'Job'].includes(item.kind) || item.metadata?.namespace !== preflight.namespace)
                : payload.kind !== 'Pod' || !args.includes('--dry-run=server') || payload.metadata?.namespace !== preflight.namespace) {
              throw new CommandError('SCOPE_DENIED', 'Canary resource creation must stay within its fixed owned resource types and namespace.');
            }
          }
          if ((args.includes('exec') || args.includes('delete')) && args[args.indexOf('--namespace') + 1] !== preflight.namespace) {
            throw new CommandError('SCOPE_DENIED', 'Canary activity cannot target another namespace.');
          }
        }
        return runner(file, args, options);
      };
      let output;
      try {
        output = await intrusiveRunner(evidence, { ...assessment.approvals.intrusive.limits, suite: action.testId,
          authorizeActive: true, confirmContext: action.context }, {
          runner: guardedRunner, signal: stageAbort.signal, progress, runIdFactory: () => preflight.runId,
          openForward: (context, namespace, options = {}) => {
            guard();
            if (context !== action.context || namespace !== preflight.namespace) throw new CommandError('SCOPE_DENIED', 'Port-forward must remain in the owned canary scope.');
            return startPortForward(context, namespace, { ...options, signal: stageAbort.signal });
          },
          persist: (partial, manifest) => persist(partial, manifest, { action, preflight })
        });
      } finally {
        clearTimeout(expiry);
        signal?.removeEventListener('abort', cancel);
      }
      const index = bundles.indexOf(evidence);
      bundles[index] = output;
      const selected = action.testId === 'all' ? Object.keys(suiteResults) : [action.testId];
      for (const suite of selected) {
        const [sourceId, predicate] = suiteResults[suite];
        const source = output.sources[sourceId];
        const cleanup = output.activeRun?.cleanup?.status;
        const complete = source?.status === 'ok' && ['deleted', 'notFound'].includes(cleanup);
        const measurement = source?.data;
        const value = !complete ? undefined : suite === 'security' ? !measurement.denied
          : suite === 'connectivity' ? !(measurement.resolved && measurement.httpStatus === 200 && measurement.markerMatched)
            : suite === 'end-to-end' ? !(measurement.attempted === 3 && measurement.successes === 3) : !measurement.statistics.withinBudgets;
        records.push(baseRecord(action, { testId: suite, stage: 'intrusive', method: 'IsolatedCanary',
          namespace: output.activeRun?.namespace, subject: kubeId(action.clusterId, 'Namespace', undefined, output.activeRun?.namespace ?? 'unresolved'),
          predicate, ...(value !== undefined ? { value } : {}), status: complete ? 'completed' : 'error',
          measurement, ownership: { runId: output.activeRun?.runId, uid: output.activeRun?.namespaceUid, cleanup },
          commands: [...commands, ...(output.activeRun?.commands ?? [])],
          ...(!complete ? { error: source?.error ?? { code: 'CLEANUP_OR_MEASUREMENT', message: 'Canary measurement or owned cleanup did not complete.' } } : {})
        }));
        if (!complete || value === true) stopped = true;
      }
    } catch (error) { failRecord(action, error, commands); stopped = true; }
  }
  return { bundles, records, stopped, usedChecks: used, plan: planAssessment(bundles, assessment, { now: now(), records }) };
}

export function validationClaims(graph, records, { now = new Date(), maxEvidenceAgeHours = 24 } = {}) {
  const claims = [];
  const gaps = [];
  for (const record of records.filter((item) => item.status === 'completed' && item.testId !== 'intrusive-preflight')) {
    const refs = graph.sources.filter((source) => source.clusterId === record.clusterId && ['cluster', 'context'].includes(source.sourceId)).map((source) => source.id);
    let claim = makeClaim({
      strategy: 'validation', subject: record.subject, predicate: record.predicate,
      scope: { clusterIds: [record.clusterId], namespace: record.namespace, resourceId: null },
      title: `Scoped ${record.method} observation: ${record.predicate}`,
      description: record.stage === 'intrusive' ? 'Measured behavior of a newly owned isolated canary only; no production attack path is validated.'
        : 'A non-mutating API response for the current authenticated subject and exact namespace; no secret content was read.',
      stance: record.value ? 'supports' : 'refutes', tier: 'validated-behavior', area: 'validation',
      baseImpact: 75, baseConfidence: 95, baseFeasibility: 65, evidenceRefs: refs, validationIds: [record.id],
      limitations: ['This result proves only the recorded behavior at its timestamp and scope.']
    });
    const matched = receiptMatches(record, claim, { graph, now, maxEvidenceAgeHours });
    if (!matched.valid) {
      gaps.push({ code: 'INVALID_VALIDATION_RECEIPT', status: 'error', validationId: record.id, reason: matched.reason });
      claim = makeClaim({ ...claim, stance: 'inconclusive', tier: 'configured-exposure', baseConfidence: 20,
        limitations: [...claim.limitations, `Recorded validation was not accepted: ${matched.reason}`] });
    }
    claims.push(claim);
  }
  return { claims, gaps: [...gaps, ...records.filter((record) => ['error', 'blocked'].includes(record.status)).map((record) =>
    ({ code: 'VALIDATION_UNAVAILABLE', actionId: record.actionId, reason: record.reason ?? record.error?.message ?? 'Validation did not complete.' }))] };
}

export function attachValidationEvidence(input, records, settings) {
  const graph = structuredClone(input);
  for (const [index, record] of records.entries()) {
    if (record.status !== 'completed' || record.testId === 'intrusive-preflight') continue;
    const claim = validationClaims(graph, [record], settings).claims[0];
    if (!claim || claim.stance === 'inconclusive') continue;
    const capability = stableId('validated-capability', [record.subject, record.predicate, record.namespace]);
    const edgeId = stableId('edge', ['validation', record.id]);
    const additionalNodes = new Set([record.subject, capability].filter((id) => !graph.nodes.some((node) => node.id === id))).size;
    const additionalEdges = graph.edges.some((edge) => edge.id === edgeId) ? 0 : 1;
    if (graph.nodes.length + additionalNodes > settings.maxNodes || graph.edges.length + additionalEdges > settings.maxEdges) {
      graph.incomplete = true;
      graph.gaps.push({ code: 'GRAPH_LIMIT', reason: 'Validation graph enrichment exceeded the configured graph size limit.' });
      throw new GraphLimitError(graph);
    }
    const ref = {
      id: stableId('evidence', ['validation', record.id]), sourceId: 'validation', clusterId: record.clusterId,
      status: 'ok', bindingStatus: 'verified', collectedAt: record.completedAt, required: false,
      document: 'diagnosis.json', pointer: `/validationRecords/${index}`,
      digest: createHash('sha256').update(canonical(record)).digest('hex'), commands: record.commands
    };
    if (!graph.sources.some((source) => source.id === ref.id)) graph.sources.push(ref);
    if (!graph.nodes.some((node) => node.id === record.subject)) {
      const identity = record.authenticatedSubject;
      graph.nodes.push({
        id: record.subject, kind: 'validation-subject', name: identity?.username ?? record.namespace,
        clusterId: record.clusterId, namespace: null, evidenceRefs: [ref.id],
        facts: { observation: [{ evidenceRef: ref.id, value: identity
          ? { username: identity.username, uid: identity.uid, groups: identity.groups ?? [] } : { ownedNamespace: record.namespace } }] }
      });
    }
    if (!graph.nodes.some((node) => node.id === capability)) graph.nodes.push({
      id: capability, kind: 'validation-observation', name: record.predicate, clusterId: record.clusterId,
      namespace: record.namespace, evidenceRefs: [ref.id],
      facts: { value: [{ evidenceRef: ref.id, value: record.value }] }
    });
    const edge = {
      id: edgeId, from: record.subject, to: capability,
      relationship: record.method === 'SelfSubjectAccessReview' ? 'validated-permission' : 'validated-behavior',
      state: 'observed', value: record.value, validationId: record.id, evidenceRefs: [ref.id]
    };
    if (!graph.edges.some((item) => item.id === edge.id)) graph.edges.push(edge);
  }
  graph.nodes.sort((a, b) => a.id.localeCompare(b.id, 'en'));
  graph.edges.sort((a, b) => a.id.localeCompare(b.id, 'en'));
  graph.sources.sort((a, b) => a.id.localeCompare(b.id, 'en'));
  return graph;
}
