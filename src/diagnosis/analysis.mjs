import { fact, stableId } from './graph.mjs';
import { makeClaim } from './reconcile.mjs';

function scope(graph, node, resourceId = node.resourceId ?? null) {
  const clusters = node.clusterId ? [node.clusterId] : graph.edges.filter((edge) => edge.to === node.id && edge.relationship === 'uses-identity')
    .map((edge) => graph.nodes.find((item) => item.id === edge.from)?.clusterId).filter(Boolean);
  return { clusterIds: [...new Set(clusters)].sort(), namespace: node.namespace ?? null, resourceId };
}

function base(node, graph, predicate, title, refs, overrides = {}) {
  return { strategy: 'exposure', subject: node.id, predicate, scope: scope(graph, node),
    title, description: title, stance: 'supports', tier: 'configured-exposure', area: 'security',
    baseImpact: 75, baseConfidence: 85, baseFeasibility: 40, evidenceRefs: refs, validationIds: [], limitations: [], ...overrides };
}

export function analyzeExposures(graph, { scenario = {} } = {}) {
  const claims = [];
  for (const edge of graph.edges.filter((item) => item.relationship === 'configured-public-entry')) {
    const node = graph.nodes.find((item) => item.id === edge.to);
    claims.push(makeClaim(base(node, graph, 'public-entry', 'Configured public workload entry', edge.evidenceRefs, {
      area: 'networking', baseImpact: 65,
      description: 'A configured public load-balancer entry selects an in-scope service. Actual reachability, firewall/policy decisions, authentication and compromise are not established.',
      recommendation: 'Confirm intended exposure, ingress authentication/TLS, effective network policy and separately authorized client reachability.'
    })));
  }
  for (const node of graph.nodes) {
    if (node.kind === 'workload') {
      const pod = fact(node, 'pod');
      if (pod.status !== 'known') {
        claims.push(makeClaim(base(node, graph, 'workload-security-unresolved', 'Workload security observations disagree or are missing', pod.evidenceRefs, { stance: 'inconclusive' })));
        continue;
      }
      const spec = pod.value.spec;
      const containers = [...spec.containers, ...(spec.initContainers ?? []), ...(spec.ephemeralContainers ?? [])];
      const privileged = containers.some((container) => container.securityContext?.privileged === true || container.securityContext?.windowsOptions?.hostProcess === true)
        || spec.securityContext?.windowsOptions?.hostProcess === true;
      const host = [spec.hostNetwork, spec.hostPID, spec.hostIPC].includes(true);
      if (privileged) claims.push(makeClaim(base(node, graph, 'container-privileged', 'Privileged or HostProcess workload configuration', pod.evidenceRefs, {
        description: 'Observed privileged/HostProcess configuration increases host-access attack surface; no container escape was executed.',
        baseImpact: 90, recommendation: 'Remove unnecessary privilege, review admission controls and document narrowly scoped platform exceptions.'
      })));
      if (host) claims.push(makeClaim(base(node, graph, 'host-namespace-sharing', 'Workload shares a host namespace', pod.evidenceRefs, {
        baseImpact: 85, description: 'Host namespace sharing is configured. Host compromise and effective isolation were not tested.'
      })));
      for (const edge of graph.edges.filter((item) => item.from === node.id && item.relationship === 'uses-service-account' && item.tokenAutomountConfigured === true)) {
        const subjects = new Set([edge.to, ...graph.edges.filter((item) => item.from === edge.to && item.relationship === 'member-of').map((item) => item.to)]);
        const grants = graph.edges.filter((item) => subjects.has(item.from) && item.relationship === 'grants-capability');
        claims.push(makeClaim(base(node, graph, 'api-token-automount', 'Automatic API credential access with service-account context', [...new Set([...pod.evidenceRefs, ...edge.evidenceRefs])], {
          area: 'identity', baseImpact: grants.length ? 85 : 55,
          description: `API-token automount is configured for the workload's service account; ${grants.length} sensitive grant declarations were linked. No token or secret value was read.`,
          recommendation: 'Remove unnecessary token mounts and review the linked service-account grants against actual application needs.'
        })));
      }
    }
    if (node.kind === 'cluster') {
      const access = fact(node, 'apiServerAccessProfile');
      if (access.status !== 'known') continue;
      const profile = access.value;
      const ranges = profile.authorizedIpRanges ?? profile.authorizedIPRanges;
      if (profile.enablePrivateCluster === false && scenario.apiAccess === 'private') {
        claims.push(makeClaim(base(node, graph, 'api-scenario-exposure', 'Public administrative API conflicts with private-API intent', access.evidenceRefs, {
          area: 'control-plane', baseImpact: 80,
          description: 'The scenario requires a private administrative endpoint, but the API is configured as public. Authorized-IP restrictions and authentication may still constrain access; reachability was not tested.'
        })));
      }
      if (profile.enablePrivateCluster === false && Array.isArray(ranges) && (!ranges.length || ranges.some((range) => /\/0$/.test(range)))) {
        claims.push(makeClaim(base(node, graph, 'api-unrestricted', 'Unrestricted public API configuration', access.evidenceRefs, {
          area: 'control-plane', baseImpact: 85, description: 'The public API has no configured authorized-IP restriction. Authentication is still required; this does not prove unauthenticated administrative access.'
        })));
      }
    }
    if (node.kind === 'azure-resource' && fact(node, 'configuration').status === 'conflicting') {
      claims.push(makeClaim(base(node, graph, 'dependency-configuration-conflict', 'Dependency configuration snapshots conflict',
        fact(node, 'configuration').evidenceRefs, { area: 'dependencies', stance: 'inconclusive', baseConfidence: 35,
          description: 'Conflicting dependency values were retained rather than selecting one snapshot as healthy.' })));
    }
  }
  return { claims, gaps: [] };
}

function pathClaim(graph, subject, predicate, title, nodes, edges, prerequisites, overrides = {}) {
  const blocked = prerequisites.some((item) => item.status === 'blocked');
  const plausible = !blocked && prerequisites.every((item) => ['satisfied', 'assumed'].includes(item.status));
  const refs = [...new Set(edges.flatMap((edge) => edge.evidenceRefs))].sort();
  return makeClaim(base(subject, graph, predicate, title, refs, {
    strategy: 'attack-paths', tier: plausible ? 'plausible-exploitability' : 'configured-exposure',
    stance: blocked ? 'refutes' : 'supports', baseImpact: 90, baseConfidence: plausible ? 70 : 50,
    baseFeasibility: plausible ? 65 : 30,
    description: 'This is a conditional attack/blast-radius hypothesis, not proof that initial compromise or exploitation occurred.',
    path: { id: stableId('path', [subject.id, predicate, nodes.map((node) => node.id)]),
      nodes: nodes.map((node) => node.id), edges: edges.map((edge) => edge.id), prerequisites },
    ...overrides
  }));
}

export function analyzeAttackPaths(graph, { scenario, maxPaths = 200 }) {
  const nodes = new Map(graph.nodes.map((node) => [node.id, node]));
  const claims = [];
  const gaps = [];
  const add = (claim) => {
    if (claims.length >= maxPaths) {
      if (!gaps.length) gaps.push({ code: 'PATH_LIMIT', reason: 'Path enumeration reached maxPaths; remaining hypotheses were not assessed.' });
      return false;
    }
    claims.push(claim);
    return true;
  };
  const compromise = (subject) => ({ id: 'initial-compromise',
    status: scenario.assumedCompromise.includes(subject.id) ? 'assumed' : 'unknown',
    description: 'Initial compromise is an explicit scenario assumption only when this exact graph node was supplied.' });
  const grantsFor = (account) => [
    ...graph.edges.filter((edge) => edge.from === account.id && edge.relationship === 'grants-capability').map((grant) => ({ grant, membership: null })),
    ...graph.edges.filter((edge) => edge.from === account.id && edge.relationship === 'member-of').flatMap((membership) =>
      graph.edges.filter((edge) => edge.from === membership.to && edge.relationship === 'grants-capability').map((grant) => ({ grant, membership })))
  ];
  const authorizationMode = (capability) => {
    const resource = graph.nodes.find((node) => node.resourceId === capability.resourceId);
    if (resource?.resourceType !== 'microsoft.keyvault/vaults') return [];
    const configuration = fact(resource, 'configuration');
    const enabled = configuration.status === 'known' ? configuration.value.enableRbacAuthorization : undefined;
    return [{ id: 'resource-authorization-mode', status: enabled === true ? 'satisfied' : enabled === false ? 'blocked' : 'unknown',
      description: 'Key Vault must use the RBAC data-plane permission model for this specific Azure-role grant path.' }];
  };
  for (const edge of graph.edges.filter((item) => item.relationship === 'uses-service-account')) {
    const workload = nodes.get(edge.from);
    const account = nodes.get(edge.to);
    const grants = grantsFor(account);
    for (const { grant, membership } of grants) {
      const capability = nodes.get(grant.to);
      if (capability.capability !== 'read-secrets') continue;
      const claim = pathClaim(graph, workload, 'workload-to-kubernetes-secrets', 'Conditional workload-to-Kubernetes-secret path',
        [workload, account, ...(membership ? [nodes.get(membership.to)] : []), capability], [edge, ...(membership ? [membership] : []), grant], [compromise(workload),
          { id: 'service-account-observed', status: account.unresolved ? 'unknown' : 'satisfied', description: 'The referenced service account must have been observed.' },
          { id: 'api-token', status: edge.tokenAutomountConfigured === true ? 'satisfied' : edge.tokenAutomountConfigured === false ? 'blocked' : 'unknown',
            description: 'Only the observed automatic-token configuration is considered; other credential mechanisms were not assessed.' },
          { id: 'sensitive-grant', status: grant.state === 'configured' ? 'satisfied' : 'unknown',
            description: 'A namespace-scoped role declaration grants secret read capability; effective permissions were not exercised.' }
        ], { area: 'identity', description: 'This conditional credential path follows token configuration and observed RBAC. It does not exclude other credential mechanisms or prove that any secret was accessed.' });
      if (!add(claim)) return { claims, gaps };
    }
    for (const federation of graph.edges.filter((item) => item.from === account.id && item.relationship === 'federates-as')) {
      const identity = nodes.get(federation.to);
      for (const grant of graph.edges.filter((item) => item.from === identity.id && item.relationship === 'grants-capability')) {
        const capability = nodes.get(grant.to);
        if (!['read-blob-data', 'read-vault-secrets'].includes(capability.capability)) continue;
        if (!add(pathClaim(graph, workload, 'workload-to-azure-data', 'Conditional federated workload-to-Azure-data path',
          [workload, account, identity, capability], [edge, federation, grant], [
            compromise(workload), { id: 'federation-configuration', status: 'satisfied', description: 'Issuer, subject and audience metadata match; token exchange was not tested.' },
            { id: 'role-conditions', status: grant.state === 'configured' ? 'satisfied' : 'unknown', description: 'Conditional role grants require independent evaluation.' },
            ...authorizationMode(capability)
          ], { scope: { ...scope(graph, workload), resourceId: capability.resourceId }, area: 'identity' }))) return { claims, gaps };
      }
    }
  }
  for (const grant of graph.edges.filter((item) => item.relationship === 'grants-capability' && nodes.get(item.from)?.kind === 'azure-principal')) {
    const identity = nodes.get(grant.from);
    const capability = nodes.get(grant.to);
    const related = graph.edges.some((item) => item.to === identity.id && ['uses-identity', 'federates-as'].includes(item.relationship));
    if (!related && !scenario.assumedCompromise.includes(identity.id)) continue;
    if (!['read-blob-data', 'read-vault-secrets', 'list-cluster-admin-credentials'].includes(capability.capability)) continue;
    const prerequisites = [compromise(identity), { id: 'role-conditions', status: grant.state === 'configured' ? 'satisfied' : 'unknown',
      description: 'The role definition grants this action. Deny assignments, PIM and external conditions were not evaluated.' }, ...authorizationMode(capability)];
    if (capability.capability === 'list-cluster-admin-credentials') {
      const cluster = graph.nodes.find((node) => node.resourceId === capability.resourceId);
      const local = fact(cluster, 'disableLocalAccounts');
      prerequisites.push({ id: 'local-accounts', status: local.status !== 'known' ? 'unknown' : local.value === true ? 'blocked' : 'satisfied',
        description: 'Disabled local accounts block this specific credential-issuance path, not every possible management-plane escalation.' });
    }
    if (!add(pathClaim(graph, identity, capability.capability === 'list-cluster-admin-credentials' ? 'identity-to-cluster-admin-credentials' : 'identity-to-azure-data',
      'Conditional Azure identity capability path', [identity, capability], [grant], prerequisites,
      { scope: { ...scope(graph, identity), resourceId: capability.resourceId }, area: 'identity' }))) return { claims, gaps };
  }
  return { claims, gaps };
}
