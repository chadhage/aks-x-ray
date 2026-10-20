import test from 'node:test';
import assert from 'node:assert/strict';
import { cidr, compareQuantities, contains, matchesSelector, overlaps, percentile, quantity } from '../src/quantities.mjs';

test('resource quantities compare decimal, binary, milli and exponent units', () => {
  for (const [input, expected] of [['100m', 0.1], ['1', 1], ['1Gi', 1073741824], ['1024Mi', 1073741824],
    ['1e3', 1000], ['1E', 1e18], ['250M', 250000000], ['500u', 0.0005], ['1n', 1e-9]]) {
    assert.equal(quantity(input), expected, input);
  }
  for (const input of [undefined, {}, 'NaN', '1garbage', '', '1e999']) assert.equal(quantity(input), null);
});

test('resource comparisons are exact across decimal units, not floating-point approximations', () => {
  assert.equal(compareQuantities('3300m', '3.3'), 0);
  assert.equal(compareQuantities('1Gi', '1024Mi'), 0);
  assert.equal(compareQuantities('100000000000000001', '100000000000000000'), 1);
  assert.equal(compareQuantities('.5', '501m'), -1);
  assert.equal(compareQuantities('invalid', '1'), null);
  assert.equal(compareQuantities('1e-999999', '1'), null);
});

test('IPv4 CIDRs handle overlap, containment and default routes exactly', () => {
  assert.equal(overlaps('10.0.0.0/16', '10.0.255.0/24'), true);
  assert.equal(overlaps('10.0.0.0/16', '10.1.0.0/16'), false);
  assert.equal(contains('10.0.0.0/16', '10.0.255.255'), true);
  assert.equal(contains('10.0.0.0/16', '10.1.0.0'), false);
  assert.equal(cidr('0.0.0.0/0').prefix, 0);
  assert.throws(() => cidr('10.0.0.0/33'), /prefix/);
});

test('dual-stack CIDRs do not silently skip IPv6 conflicts', () => {
  assert.equal(overlaps('fd00:10::/64', 'fd00:10::100/120'), true);
  assert.equal(overlaps('fd00:10::/64', 'fd00:11::/64'), false);
  assert.equal(contains('fd00:10::/64', 'fd00:10::a'), true);
  assert.equal(contains('::ffff:192.0.2.0/120', '::ffff:192.0.2.15'), true);
  assert.equal(overlaps('0.0.0.0/0', '::/0'), false);
});

test('PDB selectors implement matchLabels and Kubernetes set-based expressions', () => {
  assert.equal(matchesSelector({ app: 'web', tier: 'api' }, { matchLabels: { app: 'web' },
    matchExpressions: [{ key: 'tier', operator: 'In', values: ['api'] }] }), true);
  assert.equal(matchesSelector({}, {}), true);
  assert.equal(matchesSelector({}, null), false);
  assert.equal(matchesSelector({}, { matchExpressions: [{ key: 'blocked', operator: 'NotIn', values: ['yes'] }] }), true);
  assert.equal(matchesSelector({}, { matchExpressions: [{ key: 'app', operator: 'Exists' }] }), false);
  assert.throws(() => matchesSelector({}, { matchExpressions: [{ key: 'app', operator: 'Bad' }] }), /Unsupported/);
});

test('p95 uses nearest rank, including small sample boundaries', () => {
  assert.equal(percentile([3, 1, 2]), 3);
  assert.equal(percentile(Array.from({ length: 100 }, (_, index) => index + 1)), 95);
  assert.equal(percentile([0]), 0);
  assert.throws(() => percentile([]), /samples/);
});
