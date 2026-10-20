import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { runCommand } from '../src/process.mjs';
import { controls, validateCatalog } from '../src/catalog.mjs';
import { sourceIds, kubernetesResources } from '../src/projection.mjs';
import { assess } from '../src/engine.mjs';
import { demoEvidence } from '../examples/demo.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const counts = validateCatalog();
for (const control of controls) {
  for (const id of control.requires) if (!sourceIds.includes(id)) throw new Error(`Unknown collector ${id} in ${control.id}.`);
}
for (const platform of ['cloud', 'local']) {
  const report = assess(demoEvidence(platform));
  const failures = report.results.filter((result) => result.status === 'error');
  if (failures.length) throw new Error(`Evaluator failures: ${JSON.stringify(failures)}`);
}

async function files(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(entries.map((entry) => entry.isDirectory()
    ? files(join(directory, entry.name)) : [join(directory, entry.name)]));
  return nested.flat();
}

const checked = (await Promise.all(['bin', 'src', 'scripts', 'site', 'test', 'examples', 'schemas', 'catalog']
  .map((directory) => files(join(root, directory))))).flat();
for (const path of checked) {
  if (/\.(mjs|js)$/.test(path)) await runCommand(process.execPath, ['--check', path]);
  if (path.endsWith('.json')) JSON.parse(await readFile(path, 'utf8'));
}
const role = JSON.parse(await readFile(join(root, 'manifests', 'reader-clusterrole.yaml'), 'utf8'));
if (role.kind !== 'ClusterRole' || role.rules.some((rule) => rule.verbs.some((verb) => !['get', 'list'].includes(verb))
  || rule.resources.some((resource) => /secrets|configmaps|exec|log|proxy|\*/.test(resource)))) {
  throw new Error('Reader role must remain explicitly enumerated and read-only, without secrets or execution.');
}
for (const resource of Object.values(kubernetesResources)) {
  const [name, ...group] = resource.split('.');
  if (!role.rules.some((rule) => rule.resources.includes(name) && rule.apiGroups.includes(group.join('.')))) {
    throw new Error(`Reader role does not cover ${resource}.`);
  }
}
const css = await readFile(join(root, 'site', 'styles.css'), 'utf8');
const components = css.slice(css.indexOf('* {'));
if (/#[0-9a-f]{3,8}\b|(?:rgba?|hsla?)\(/i.test(components) || /@import|url\(/i.test(css)) {
  throw new Error('Component styles must use Clawpilot theme variables and no remote assets.');
}
console.log(`Validated syntax, JSON, read-only RBAC coverage, theme and catalogue: ${counts.controls} controls, ${counts.categories} categories, ${counts.sources} Microsoft sources.`);
