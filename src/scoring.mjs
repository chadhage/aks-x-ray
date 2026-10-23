import { categories, controls } from './catalog.mjs';
import { namespacedSources } from './projection.mjs';

export function ratingRuntime(controls, categories, namespacedSources) {
  const controlById = new Map(controls.map((control) => [control.id, control]));
  const namespaced = new Set(namespacedSources);
  const weights = { high: 5, medium: 3, low: 1, info: 1 };
  const pillars = [
    ['reliability', 'Reliability'], ['security', 'Security'], ['cost-optimization', 'Cost optimization'],
    ['operational-excellence', 'Operational excellence'], ['performance-efficiency', 'Performance efficiency']
  ];
  const statuses = ['pass', 'fail', 'review', 'unknown', 'error', 'notApplicable', 'notRun'];
  const namespaceControls = (categoryIds) => controls.filter((control) => categoryIds.includes(control.category)
    && control.requires.some((id) => id === 'namespaces' || namespaced.has(id)));

  function score(result, bindingStatus) {
    if (bindingStatus !== 'verified' || result.incomplete || !['pass', 'fail'].includes(result.status)) return null;
    const checked = result.observed?.checked;
    const deviations = result.observed?.deviations?.count;
    if (checked !== undefined && deviations !== undefined) {
      if (!Number.isInteger(checked) || checked < 1 || !Number.isInteger(deviations) || deviations < 0 || deviations > checked
        || result.status === 'pass' && deviations !== 0 || result.status === 'fail' && deviations === 0) {
        throw new Error('Inconsistent scored observation counts.');
      }
      return Math.round(1 + 99 * (checked - deviations) / checked);
    }
    return result.status === 'pass' ? 100 : 1;
  }

  function group(results, bindingStatus) {
    const applicable = results.filter((result) => result.status !== 'notApplicable');
    const scored = applicable.map((result) => ({ result, score: score(result, bindingStatus) })).filter((item) => item.score !== null);
    const weight = scored.reduce((sum, item) => sum + weights[controlById.get(item.result.id).severity], 0);
    return {
      score: weight ? Math.round(scored.reduce((sum, item) => sum + item.score * weights[controlById.get(item.result.id).severity], 0) / weight) : null,
      applicable: applicable.length, scored: scored.length, unscored: applicable.length - scored.length,
      coveragePercent: applicable.length ? Math.round(scored.length / applicable.length * 100) : null,
      controlIds: results.map((result) => result.id)
    };
  }

  function build(results, namespaceResults, bindingStatus, categoryIds) {
    const selectedCategories = categories.filter((category) => categoryIds.includes(category.id));
    return {
      methodology: {
        id: 'aks-xray-evidence-v1', projectDefined: true, scale: [1, 100], weights: { ...weights },
        explanation: 'Project-defined configuration adherence, not a Microsoft score, compliance certification, CVSS or proof of exploitability. Read scored-subset coverage and unresolved findings together.'
      },
      overall: { id: 'overall', title: 'Scored configuration subset', ...group(results, bindingStatus) },
      areas: selectedCategories.map((category) => ({
        id: category.id, title: category.title, ...group(results.filter((result) => controlById.get(result.id).category === category.id), bindingStatus)
      })),
      pillars: pillars.map(([id, title]) => {
        const areaIds = selectedCategories.filter((category) => category.pillars.includes(id)).map((category) => category.id);
        return { id, title, ...group(results.filter((result) => areaIds.includes(controlById.get(result.id).category)), bindingStatus) };
      }),
      namespaces: namespaceResults.map((entry) => ({
        id: entry.namespace, title: entry.namespace, ...group(entry.results, bindingStatus)
      }))
    };
  }

  function same(a, b) {
    if (a === b) return true;
    if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object' || Array.isArray(a) !== Array.isArray(b)) return false;
    const keys = Object.keys(a);
    return keys.length === Object.keys(b).length && keys.every((key) => Object.hasOwn(b, key) && same(a[key], b[key]));
  }

  function validate(assessment) {
    const checkScores = (results) => {
      for (const result of results) {
        if (!controlById.has(result.id) || !statuses.includes(result.status) || typeof result.incomplete !== 'boolean'
          || typeof result.message !== 'string' || !Array.isArray(result.evidence)
          || result.score !== score(result, assessment.target.binding.status)) throw new Error('Invalid or forged configuration score.');
      }
    };
    checkScores(assessment.results);
    if (!Array.isArray(assessment.namespaceResults)) throw new Error('Namespace rating results are required.');
    const expectedIds = namespaceControls(assessment.scope.categories).map((control) => control.id);
    const seen = new Set();
    for (const entry of assessment.namespaceResults) {
      if (typeof entry.namespace !== 'string' || !/^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(entry.namespace)
        || entry.namespace.length > 63 || seen.has(entry.namespace) || assessment.scope.excludedNamespaces.includes(entry.namespace)
        || assessment.scope.namespaces !== null && !assessment.scope.namespaces.includes(entry.namespace)
        || !Array.isArray(entry.results) || entry.results.length !== expectedIds.length
        || new Set(entry.results.map((result) => result.id)).size !== expectedIds.length
        || expectedIds.some((id) => !entry.results.some((result) => result.id === id))) throw new Error('Invalid or incomplete namespace score results.');
      seen.add(entry.namespace);
      checkScores(entry.results);
    }
    if (assessment.scope.namespaces?.some((name) => !seen.has(name))) throw new Error('Missing explicitly selected namespace ratings.');
    const expected = build(assessment.results, assessment.namespaceResults, assessment.target.binding.status, assessment.scope.categories);
    if (!same(expected, assessment.ratings)) throw new Error('Assessment ratings do not match the scored findings.');
  }

  return { score, group, build, validate, namespaceControls };
}

export const rating = ratingRuntime(controls, categories, [...namespacedSources]);
