import { isIP } from 'node:net';

const decimal = { n: 1e-9, u: 1e-6, m: 1e-3, '': 1, k: 1e3, K: 1e3, M: 1e6, G: 1e9, T: 1e12, P: 1e15, E: 1e18 };
const binary = { Ki: 2 ** 10, Mi: 2 ** 20, Gi: 2 ** 30, Ti: 2 ** 40, Pi: 2 ** 50, Ei: 2 ** 60 };
const quantityPattern = /^([+-]?(?:\d+(?:\.\d*)?|\.\d+))((?:[eE][+-]?\d+)|[numkKMGTPE]|[KMGTPE]i)?$/;

export function quantity(value) {
  if (typeof value !== 'string' && typeof value !== 'number') return null;
  if (String(value).length > 128) return null;
  const match = String(value).match(quantityPattern);
  if (!match) return null;
  const suffix = match[2] ?? '';
  const multiplier = /^[eE][+-]?\d+$/.test(suffix) ? 10 ** Number(suffix.slice(1))
    : binary[suffix] ?? decimal[suffix];
  const number = Number(match[1]) * multiplier;
  return Number.isFinite(number) ? number : null;
}

function rationalQuantity(value) {
  if (quantity(value) === null) return null;
  const [, numeric, suffix = ''] = String(value).match(quantityPattern);
  const fraction = numeric.includes('.') ? numeric.split('.')[1].length : 0;
  let numerator = BigInt(numeric.replace('.', ''));
  let denominator = 10n ** BigInt(fraction);
  if (Object.hasOwn(binary, suffix)) numerator *= BigInt(binary[suffix]);
  else {
    const exponent = /^[eE][+-]?\d+$/.test(suffix) ? Number(suffix.slice(1))
      : ({ n: -9, u: -6, m: -3, '': 0, k: 3, K: 3, M: 6, G: 9, T: 12, P: 15, E: 18 })[suffix];
    if (!Number.isSafeInteger(exponent) || Math.abs(exponent) > 400) return null;
    if (exponent >= 0) numerator *= 10n ** BigInt(exponent);
    else denominator *= 10n ** BigInt(-exponent);
  }
  return { numerator, denominator };
}

export function compareQuantities(left, right) {
  const a = rationalQuantity(left);
  const b = rationalQuantity(right);
  if (!a || !b) return null;
  const difference = a.numerator * b.denominator - b.numerator * a.denominator;
  return difference < 0n ? -1 : difference > 0n ? 1 : 0;
}

function ipNumber(address) {
  const family = isIP(address);
  if (family === 4) {
    return { bits: 32, value: address.split('.').reduce((value, octet) => (value << 8n) | BigInt(octet), 0n) };
  }
  if (family !== 6) throw new Error(`Invalid IP address: ${address}`);
  let expanded = address;
  if (expanded.includes('.')) {
    const colon = expanded.lastIndexOf(':');
    const ipv4 = ipNumber(expanded.slice(colon + 1)).value;
    expanded = `${expanded.slice(0, colon)}:${(ipv4 >> 16n).toString(16)}:${(ipv4 & 65535n).toString(16)}`;
  }
  const halves = expanded.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const groups = halves.length === 2 ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left;
  return { bits: 128, value: groups.reduce((value, group) => (value << 16n) | BigInt(`0x${group}`), 0n) };
}

export function cidr(value) {
  if (typeof value !== 'string') throw new Error('CIDR must be a string.');
  const parts = value.split('/');
  if (parts.length !== 2 || !/^\d+$/.test(parts[1])) throw new Error(`Invalid CIDR: ${value}`);
  const { bits, value: ip } = ipNumber(parts[0]);
  const prefix = Number(parts[1]);
  if (prefix < 0 || prefix > bits) throw new Error(`Invalid CIDR prefix: ${value}`);
  const width = BigInt(bits - prefix);
  const start = (ip >> width) << width;
  return { bits, prefix, start, end: start + (1n << width) - 1n };
}

export function overlaps(a, b) {
  const left = cidr(a);
  const right = cidr(b);
  return left.bits === right.bits && left.start <= right.end && right.start <= left.end;
}

export function contains(network, address) {
  const range = cidr(network);
  const ip = ipNumber(address);
  return range.bits === ip.bits && ip.value >= range.start && ip.value <= range.end;
}

export function percentile(values, percent = 95) {
  if (!values.length || values.some((value) => !Number.isFinite(value) || value < 0)
    || percent <= 0 || percent > 100) throw new Error('Percentile needs nonnegative finite samples and 0 < percent <= 100.');
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.ceil((percent / 100) * sorted.length) - 1];
}

export function matchesSelector(labels, selector) {
  if (selector === null || selector === undefined) return false;
  if (selector.matchLabels && Object.entries(selector.matchLabels).some(([key, value]) => labels[key] !== value)) return false;
  return (selector.matchExpressions ?? []).every(({ key, operator, values }) => {
    switch (operator) {
      case 'In': return Array.isArray(values) && values.includes(labels[key]);
      case 'NotIn': return Array.isArray(values) && !values.includes(labels[key]);
      case 'Exists': return Object.hasOwn(labels, key);
      case 'DoesNotExist': return !Object.hasOwn(labels, key);
      default: throw new Error(`Unsupported label-selector operator: ${operator}`);
    }
  });
}
