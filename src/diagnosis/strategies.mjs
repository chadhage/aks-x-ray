import { workloadSources } from '../projection.mjs';

export const assessmentStrategies = ['configuration', 'graph', 'exposure', 'attack-paths', 'validation'];
export const validationStages = ['passive', 'non-mutating', 'intrusive'];
export const evidenceTiers = ['configured-exposure', 'plausible-exploitability', 'validated-behavior'];
export const graphSources = ['nodes', 'namespaces', ...workloadSources, 'services', 'endpointslices', 'ingresses',
  'networkpolicies', 'serviceaccounts', 'roles', 'rolebindings', 'clusterroles', 'clusterrolebindings',
  'relatedResources', 'roleAssignments', 'roleDefinitions', 'federatedCredentials', 'resourceGraph'];
export const nonMutatingTests = ['authorization-review', 'admission-dry-run', 'intrusive-preflight'];
export const intrusiveSuites = ['connectivity', 'end-to-end', 'load', 'security'];
