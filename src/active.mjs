import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { setTimeout as sleep } from 'node:timers/promises';
import { binding } from './collector.mjs';
import { validateEvidence } from './evidence.mjs';
import { projectSource } from './projection.mjs';
import { CommandError, commandFailure, invocation, runCommand } from './process.mjs';
import { loadStatistics } from './rules.mjs';
import { sourceCatalog } from './catalog.mjs';
import { isGuid, verifySubscriptions } from './scope.mjs';

export const marker = 'AKS-X-RAY-SYNTHETIC-OK';
export const activeImage = sourceCatalog.activeImage.reference;
export const suites = ['connectivity', 'end-to-end', 'load', 'security'];
const suiteSources = { connectivity: 'activeConnectivity', 'end-to-end': 'activeE2E', load: 'activeLoad', security: 'activeSecurity' };
const managedBy = 'aks-xray';
const ownerLabel = 'app.kubernetes.io/instance';
const serverCode = `from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"${marker}"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
`;

export function validateActiveOptions(options, evidence) {
  validateEvidence(evidence);
  if (evidence.synthetic) throw new Error('Live tests cannot use synthetic evidence. Collect a real target first.');
  if (['pending', 'error'].includes(evidence.activeRun?.cleanup?.status)) {
    throw new Error('Resolve the previous active run cleanup before starting another run from this evidence.');
  }
  if (options.authorizeActive !== true || options.confirmContext !== evidence.target.context) {
    throw new Error('Active tests require --authorize-active and --confirm-context matching the evidence context exactly.');
  }
  const targetBinding = binding(evidence);
  if (targetBinding.status !== 'verified' || targetBinding.mode === 'arm-only') throw new Error('Active tests require a verified context-to-ARM endpoint binding. Collect with the Kubernetes strategy first.');
  const selected = options.suite === 'all' ? [...suites] : [options.suite];
  if (selected.some((suite) => !suites.includes(suite))) throw new Error(`Suite must be all or one of: ${suites.join(', ')}.`);
  const limits = {
    requests: options.requests ?? 40, concurrency: options.concurrency ?? 2,
    durationSeconds: options.durationSeconds ?? 10, workerPacingMs: 100
  };
  const budgets = { p95Ms: options.latencyBudgetMs ?? 2000, maxErrorRatePercent: options.errorBudgetPercent ?? 0 };
  loadStatistics({ limits, budgets, samples: [{ ok: true, latencyMs: 0 }], durationMs: 0 });
  return { selected, limits, budgets };
}

export function syntheticNamespace(namespace, runId) {
  return {
    apiVersion: 'v1', kind: 'Namespace',
    metadata: { name: namespace, labels: {
      'app.kubernetes.io/managed-by': managedBy, [ownerLabel]: runId,
      'pod-security.kubernetes.io/enforce': 'restricted',
      'pod-security.kubernetes.io/enforce-version': 'latest',
      'pod-security.kubernetes.io/audit': 'restricted',
      'pod-security.kubernetes.io/warn': 'restricted'
    } }
  };
}

function syntheticPod(role, runId) {
  return {
    metadata: { labels: { 'app.kubernetes.io/name': `aks-xray-${role}`, [ownerLabel]: runId } },
    spec: {
      restartPolicy: 'Never', automountServiceAccountToken: false,
      nodeSelector: { 'kubernetes.io/os': 'linux', 'kubernetes.io/arch': 'amd64' },
      securityContext: { runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, seccompProfile: { type: 'RuntimeDefault' } },
      containers: [{
        name: role, image: activeImage, imagePullPolicy: 'Always',
        command: ['python3', '-c', role === 'server' ? serverCode : 'import time; time.sleep(240)'],
        env: [{ name: 'PYTHONDONTWRITEBYTECODE', value: '1' }, { name: 'PYTHONUNBUFFERED', value: '1' }],
        resources: { requests: { cpu: '100m', memory: '128Mi' }, limits: { cpu: '250m', memory: '256Mi' } },
        securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ['ALL'] } },
        ...(role === 'server' ? {
          ports: [{ containerPort: 8080 }],
          readinessProbe: { httpGet: { path: '/healthz', port: 8080 }, initialDelaySeconds: 1, periodSeconds: 2 },
          livenessProbe: { httpGet: { path: '/healthz', port: 8080 }, initialDelaySeconds: 5, periodSeconds: 5 }
        } : {})
      }]
    }
  };
}

export function syntheticResources(namespace, runId) {
  const resource = (kind, apiVersion, name, body) => ({
    apiVersion, kind, metadata: { name, namespace, labels: { 'app.kubernetes.io/managed-by': managedBy, [ownerLabel]: runId } }, ...body
  });
  const jobs = ['server', 'probe'].map((role) => resource('Job', 'batch/v1', `aks-xray-${role}`, {
    spec: { backoffLimit: 0, activeDeadlineSeconds: 240, ttlSecondsAfterFinished: 60, template: syntheticPod(role, runId) }
  }));
  return { apiVersion: 'v1', kind: 'List', items: [
    resource('ResourceQuota', 'v1', 'xray-budget', { spec: { hard: {
      pods: '3', 'requests.cpu': '500m', 'requests.memory': '512Mi', 'limits.cpu': '1', 'limits.memory': '1Gi',
      services: '1', 'count/jobs.batch': '2'
    } } }),
    resource('NetworkPolicy', 'networking.k8s.io/v1', 'default-deny', {
      spec: { podSelector: {}, policyTypes: ['Ingress', 'Egress'], ingress: [], egress: [] }
    }),
    resource('NetworkPolicy', 'networking.k8s.io/v1', 'synthetic-paths', {
      spec: { podSelector: { matchLabels: { [ownerLabel]: runId } }, policyTypes: ['Ingress', 'Egress'],
        ingress: [{ from: [{ podSelector: { matchLabels: { [ownerLabel]: runId } } }], ports: [{ port: 8080, protocol: 'TCP' }] }],
        egress: [
          { ports: [{ port: 53, protocol: 'UDP' }, { port: 53, protocol: 'TCP' }] },
          { to: [{ podSelector: { matchLabels: { 'app.kubernetes.io/name': 'aks-xray-server', [ownerLabel]: runId } } }],
            ports: [{ port: 8080, protocol: 'TCP' }] }
        ]
      }
    }),
    resource('Service', 'v1', 'aks-xray-server', {
      spec: { type: 'ClusterIP', selector: { 'app.kubernetes.io/name': 'aks-xray-server', [ownerLabel]: runId },
        ports: [{ port: 8080, targetPort: 8080, protocol: 'TCP' }] }
    }),
    ...jobs
  ] };
}

export async function httpProbe(url, timeoutMs = 2000) {
  const parsed = new URL(url);
  if (parsed.protocol !== 'http:' || parsed.hostname !== '127.0.0.1') {
    throw new Error('Synthetic HTTP probes are restricted to the owned loopback port-forward.');
  }
  const started = performance.now();
  try {
    const response = await fetch(url, { signal: AbortSignal.timeout(Math.max(1, Math.floor(timeoutMs))), redirect: 'error' });
    let body = '';
    for await (const chunk of response.body) {
      if (Buffer.byteLength(body) + chunk.length > 4096) {
        return { ok: false, latencyMs: performance.now() - started, status: response.status, errorCode: 'BODY_LIMIT' };
      }
      body += Buffer.from(chunk).toString('utf8');
    }
    return { ok: response.status === 200 && body === marker, latencyMs: performance.now() - started, status: response.status };
  } catch (error) {
    if (!(error instanceof TypeError) && !['TimeoutError', 'AbortError'].includes(error.name)) throw error;
    return { ok: false, latencyMs: performance.now() - started, status: 0,
      errorCode: ['TimeoutError', 'AbortError'].includes(error.name) ? 'TIMEOUT' : 'TRANSPORT' };
  }
}

export async function performLoad(url, limits, budgets, { request = httpProbe, signal } = {}) {
  loadStatistics({ limits, budgets, samples: [{ ok: true, latencyMs: 0 }], durationMs: 0 });
  const started = performance.now();
  const deadline = started + limits.durationSeconds * 1000;
  const samples = [];
  let scheduled = 0;
  await Promise.all(Array.from({ length: limits.concurrency }, async (_, worker) => {
    let nextAttemptAt = started;
    while (scheduled < limits.requests && performance.now() < deadline) {
      if (signal?.aborted) throw new CommandError('ABORTED', 'Load smoke was cancelled.');
      const delay = nextAttemptAt - performance.now();
      if (delay > 0) {
        if (nextAttemptAt >= deadline) break;
        await sleep(Math.ceil(delay), undefined, { signal });
        continue;
      }
      scheduled++;
      const startedAtMs = performance.now() - started;
      const sample = await request(url, Math.min(2000, Math.max(1, deadline - performance.now())));
      samples.push({ ...sample, worker, startedAtMs });
      nextAttemptAt = performance.now() + limits.workerPacingMs;
    }
  }));
  const data = { limits, budgets, samples, durationMs: performance.now() - started, path: 'loopback-port-forward',
    stoppedBy: scheduled >= limits.requests ? 'request-cap' : 'duration-cap' };
  return { ...data, statistics: loadStatistics(data) };
}

export async function startPortForward(context, namespace, { signal, spawnProcess = spawn } = {}) {
  const args = ['--context', context, '--namespace', namespace, '--request-timeout=0',
    'port-forward', 'service/aks-xray-server', ':8080', '--address=127.0.0.1'];
  const resolved = invocation('kubectl', args);
  return new Promise((resolve, reject) => {
    const child = spawnProcess(resolved.file, resolved.args, { shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let ready = false;
    let closed = false;
    let output = '';
    let closeResolve;
    const onClose = new Promise((done) => { closeResolve = done; });
    const abort = () => child.kill();
    signal?.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(() => {
      child.kill();
      reject(new CommandError('TIMEOUT', 'Loopback port-forward did not become ready in 15 seconds.'));
    }, 15_000);
    const close = async () => {
      if (!closed) child.kill();
      await onClose;
    };
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      output = (output + chunk).slice(-8192);
      const match = output.match(/Forwarding from 127\.0\.0\.1:(\d+) -> 8080/);
      if (match && !ready) {
        ready = true;
        clearTimeout(timer);
        resolve({ url: `http://127.0.0.1:${match[1]}/healthz`, close });
      }
    });
    child.stderr.on('data', () => {});
    child.on('error', (error) => {
      clearTimeout(timer);
      reject(new CommandError(error.code ?? 'SPAWN', `Unable to start the port-forward: ${error.code}.`));
    });
    child.on('close', () => {
      closed = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      closeResolve();
      if (!ready) reject(new CommandError('PORT_FORWARD', 'The owned port-forward exited before becoming ready.'));
    });
    if (signal?.aborted) abort();
  });
}

async function waitForPods(kube, namespace, signal) {
  const deadline = performance.now() + 90_000;
  while (performance.now() < deadline) {
    const response = await kube(['get', 'pods', '--namespace', namespace, '--output=json'],
      { timeoutMs: Math.max(1, Math.min(15_000, deadline - performance.now())) });
    const data = JSON.parse(response.stdout);
    if (!Array.isArray(data.items)) throw new Error('Readiness polling received an invalid PodList.');
    if (data.items.some((pod) => pod.status?.phase === 'Failed')) throw new Error('A synthetic job pod failed before becoming ready.');
    const ready = ['server', 'probe'].every((role) => data.items.some((pod) =>
      pod.metadata?.labels?.['app.kubernetes.io/name'] === `aks-xray-${role}`
      && pod.status?.conditions?.some((condition) => condition.type === 'Ready' && condition.status === 'True')));
    if (ready) return;
    await sleep(Math.min(500, Math.max(0, deadline - performance.now())), undefined, { signal });
  }
  throw new CommandError('READINESS_TIMEOUT', 'Synthetic pods did not become Ready in 90 seconds; review image access, policy and Linux capacity.');
}

export async function cleanupNamespace(kube, namespace, runId, uid) {
  try {
    const response = await kube(['get', 'namespace', namespace, '--output=json'], { signal: undefined });
    const observed = JSON.parse(response.stdout);
    if (observed.metadata?.labels?.['app.kubernetes.io/managed-by'] !== managedBy
      || observed.metadata?.labels?.[ownerLabel] !== runId || uid && observed.metadata?.uid !== uid) {
      throw new Error('Ownership mismatch: refusing to delete a namespace not proven to belong to this run.');
    }
    await kube(['delete', 'namespace', namespace, '--wait=true', '--timeout=45s'], { timeoutMs: 50_000, signal: undefined });
    return { status: 'deleted', completedAt: new Date().toISOString(), namespace };
  } catch (error) {
    if (error instanceof CommandError && commandFailure(error).code === 'NOT_FOUND') {
      return { status: 'notFound', completedAt: new Date().toISOString(), namespace };
    }
    return { status: 'error', completedAt: new Date().toISOString(), namespace, error: commandFailure(error) };
  }
}

export async function runActive(input, options, {
  runner = runCommand, openForward = startPortForward, request = httpProbe,
  persist = async () => {}, progress = () => {}, signal, runIdFactory = randomUUID
} = {}) {
  const { selected, limits, budgets } = validateActiveOptions(options, input);
  const evidence = structuredClone(input);
  const context = evidence.target.context;
  const runId = runIdFactory();
  if (!isGuid(runId)) throw new Error('Active run ID must be an internally generated UUID.');
  const namespace = `aks-xray-${runId.slice(0, 18)}`;
  const commands = [];
  let recording;
  if (evidence.target.tenant) {
    const accountCommands = [];
    const verified = await verifySubscriptions({ tenant: evidence.target.tenant, subscriptions: evidence.scope.authorizedSubscriptions }, {
      runner: (file, args) => {
        const command = { file, args };
        commands.push(command);
        accountCommands.push(command);
        return runner(file, args, { signal });
      }
    });
    evidence.sources.accounts = { status: 'ok', collectedAt: new Date().toISOString(), commands: accountCommands,
      data: { items: verified.subscriptions } };
  }
  const kube = (args, overrides = {}) => {
    const command = { file: 'kubectl', args: ['--context', context, '--request-timeout=20s', ...args] };
    commands.push(command);
    recording?.commands.push(command);
    return runner(command.file, command.args, { signal, ...overrides });
  };
  const current = await kube(['config', 'view', '--minify', '--output=jsonpath={.clusters[0].cluster.server}']);
  if (projectSource('context', current.stdout).server !== evidence.sources.context.data.server) {
    throw new Error('The context endpoint changed since evidence collection. Recollect before any active test.');
  }
  if (!evidence.scope.categories.includes('active-validation')) evidence.scope.categories.push('active-validation');
  evidence.activeRun = {
    runId, namespace, startedAt: new Date().toISOString(), suites: selected,
    authorization: { explicit: true, confirmedContext: context },
    image: activeImage, limits, budgets, commands, cleanup: { status: 'pending' }
  };
  for (const suite of selected) {
    evidence.sources[suiteSources[suite]] = {
      status: 'notCollected', collectedAt: evidence.activeRun.startedAt, reason: 'Authorized active run is pending.', runId
    };
  }
  const manifest = syntheticResources(namespace, runId);
  await persist(evidence, manifest);
  let attemptedNamespace = false;
  let namespaceUid;
  let forward;
  const record = async (suite, operation) => {
    const sourceId = suiteSources[suite];
    const started = performance.now();
    const source = { status: 'ok', collectedAt: new Date().toISOString(), namespace, runId, commands: [] };
    recording = source;
    progress(`Running isolated ${suite} test in ${namespace}`);
    try {
      source.data = await operation();
    } catch (error) {
      source.status = 'error';
      source.error = commandFailure(error);
      progress(`Active test error [${suite}]: ${source.error.code}: ${source.error.message}`);
    }
    source.durationMs = performance.now() - started;
    recording = undefined;
    evidence.sources[sourceId] = source;
    await persist(evidence, manifest);
  };
  try {
    attemptedNamespace = true;
    const created = await kube(['create', '--filename=-', '--output=json'], { input: JSON.stringify(syntheticNamespace(namespace, runId)) });
    namespaceUid = JSON.parse(created.stdout).metadata?.uid;
    if (typeof namespaceUid !== 'string' || !namespaceUid) throw new Error('Created namespace response did not contain its UID.');
    evidence.activeRun.namespaceUid = namespaceUid;
    await persist(evidence, manifest);
    await kube(['create', '--filename=-', '--output=json'], { input: JSON.stringify(manifest), timeoutMs: 45_000 });
    await waitForPods(kube, namespace, signal);
    if (selected.includes('connectivity')) {
      await record('connectivity', async () => {
        const code = `import socket,urllib.request,json\naddresses=socket.getaddrinfo("aks-xray-server",8080)\nr=urllib.request.urlopen("http://aks-xray-server:8080/healthz",timeout=5)\nprint(json.dumps({"resolved":bool(addresses),"addresses":len(addresses),"httpStatus":r.status,"markerMatched":r.read(4097).decode()=="${marker}"}))`;
        const response = await kube(['exec', '--namespace', namespace, 'job/aks-xray-probe', '--', 'python3', '-c', code], { timeoutMs: 15_000 });
        return JSON.parse(response.stdout);
      });
    }
    if (selected.includes('end-to-end') || selected.includes('load')) {
      forward = await openForward(context, namespace, { signal });
    }
    if (selected.includes('end-to-end')) {
      await record('end-to-end', async () => {
        const samples = [];
        for (let index = 0; index < 3; index++) samples.push(await request(forward.url, 2000));
        return { attempted: samples.length, successes: samples.filter((sample) => sample.ok).length, samples, path: 'loopback-port-forward' };
      });
    }
    if (selected.includes('load')) await record('load', () => performLoad(forward.url, limits, budgets, { request, signal }));
    if (selected.includes('security')) {
      await record('security', async () => {
        const pod = syntheticPod('probe', runId);
        pod.spec.containers[0].securityContext.privileged = true;
        const denied = { apiVersion: 'v1', kind: 'Pod', ...pod, metadata: { ...pod.metadata, name: 'xray-admission-negative', namespace } };
        try {
          await kube(['create', '--dry-run=server', '--filename=-', '--output=json'], { input: JSON.stringify(denied) });
          return { denied: false, dryRun: true, reason: 'accepted' };
        } catch (error) {
          if (!(error instanceof CommandError) || !/violates PodSecurity\s+["']restricted/i.test(error.stderr)) throw error;
          return { denied: true, dryRun: true, reason: 'restricted-pod-security' };
        }
      });
    }
  } catch (error) {
    evidence.activeRun.error = commandFailure(error);
    progress(`Active run failed: ${evidence.activeRun.error.code}: ${evidence.activeRun.error.message}`);
    for (const suite of selected) {
      const sourceId = suiteSources[suite];
      if (evidence.sources[sourceId]?.runId !== runId || evidence.sources[sourceId]?.status === 'notCollected') {
        evidence.sources[sourceId] = { status: 'error', collectedAt: new Date().toISOString(),
          runId, namespace, commands: [],
          error: { code: 'RUN_ABORTED', message: 'The authorized synthetic run failed before this test completed.' } };
      }
    }
  } finally {
    try {
      if (forward) await forward.close();
    } finally {
      evidence.activeRun.cleanup = attemptedNamespace
        ? await cleanupNamespace(kube, namespace, runId, namespaceUid) : { status: 'notNeeded' };
      evidence.activeRun.completedAt = new Date().toISOString();
      if (evidence.activeRun.cleanup.status === 'error') progress(`CLEANUP FAILED: ${namespace}. Review recorded ownership and runbook; no unrelated namespace was deleted.`);
      await persist(evidence, manifest);
    }
  }
  return evidence;
}
