import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const read = (name) => JSON.parse(readFileSync(new URL(`../catalog/${name}.json`, import.meta.url), 'utf8'));
export const categories = read('categories');
export const controls = read('controls');
export const sourceCatalog = read('sources');
export const catalogVersion = sourceCatalog.catalogVersion;
export const toolVersion = '0.3.0';
export const catalogDigest = createHash('sha256').update(JSON.stringify({ categories, controls, sourceCatalog })).digest('hex');
export const statuses = ['pass', 'fail', 'review', 'unknown', 'error', 'notApplicable', 'notRun'];
export const severities = ['high', 'medium', 'low', 'info'];

export function selectControls(categoryIds = categories.map(({ id }) => id)) {
  for (const id of categoryIds) {
    if (!categories.some((category) => category.id === id)) throw new Error(`Unknown category: ${id}`);
  }
  return controls.filter((control) => categoryIds.includes(control.category));
}

export function validateCatalog() {
  if (!/^mcr\.microsoft\.com\/azure-cli@sha256:[0-9a-f]{64}$/.test(sourceCatalog.activeImage?.reference)) {
    throw new Error('The active runtime must be an explicitly pinned official Microsoft image.');
  }
  const ids = new Set();
  const pillars = ['reliability', 'security', 'cost-optimization', 'operational-excellence', 'performance-efficiency'];
  for (const category of categories) {
    if (!Array.isArray(category.pillars) || !category.pillars.length || new Set(category.pillars).size !== category.pillars.length
      || category.pillars.some((pillar) => !pillars.includes(pillar))) throw new Error(`Invalid WAF pillar mapping: ${category.id}`);
  }
  const sourceIds = new Set(sourceCatalog.sources.map(({ id }) => id));
  for (const source of sourceCatalog.sources) {
    const url = new URL(source.url);
    if (url.protocol !== 'https:' || url.hostname !== 'learn.microsoft.com') {
      throw new Error(`Unapproved assessment source: ${source.id}`);
    }
  }
  for (const control of controls) {
    if (ids.has(control.id)) throw new Error(`Duplicate control: ${control.id}`);
    ids.add(control.id);
    selectControls([control.category]);
    if (!severities.includes(control.severity)) throw new Error(`Invalid severity: ${control.id}`);
    if (!['passive', 'manual', 'active'].includes(control.mode)) throw new Error(`Invalid mode: ${control.id}`);
    if (!control.platforms.length || control.platforms.some((value) => !['cloud', 'local'].includes(value))) {
      throw new Error(`Invalid platform: ${control.id}`);
    }
    if (!control.assertion || !control.remediation || !control.sourceIds.length) {
      throw new Error(`Incomplete control: ${control.id}`);
    }
    for (const id of control.sourceIds) {
      if (!sourceIds.has(id)) throw new Error(`Unknown source ${id} in ${control.id}`);
    }
  }
  return { controls: controls.length, categories: categories.length, sources: sourceIds.size };
}
