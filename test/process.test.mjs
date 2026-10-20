import test from 'node:test';
import assert from 'node:assert/strict';
import { invocation, runCommand, commandFailure, CommandError } from '../src/process.mjs';

test('process runner preserves stdout and terminates failed, oversized and timed-out commands', async () => {
  assert.equal((await runCommand(process.execPath, ['-e', 'process.stdout.write("ok")'])).stdout, 'ok');
  await assert.rejects(() => runCommand(process.execPath, ['-e', 'process.exit(3)']), (error) => error.exitCode === 3);
  await assert.rejects(() => runCommand(process.execPath, ['-e', 'process.stdout.write("x".repeat(1000))'], { maxBytes: 100 }),
    (error) => error.code === 'OUTPUT_LIMIT');
  await assert.rejects(() => runCommand(process.execPath, ['-e', 'setInterval(()=>{}, 1000)'], { timeoutMs: 100 }),
    (error) => error.code === 'TIMEOUT');
});

test('process runner supports cancellation and missing executables explicitly', async () => {
  const abort = new AbortController();
  abort.abort();
  await assert.rejects(() => runCommand(process.execPath, [], { signal: abort.signal }), (error) => error.code === 'ABORTED');
  await assert.rejects(() => runCommand('aks-xray-intentionally-missing-tool', []), (error) => error.code === 'ENOENT');
});

test('Windows az.cmd adapter quotes literal arguments and refuses shell metacharacters', () => {
  const result = invocation('az', ['aks', 'show', '--resource-group', "a group's name"], 'win32', null);
  const script = Buffer.from(result.args.at(-1), 'base64').toString('utf16le');
  assert.match(script, /a group''s name/);
  for (const input of ['x&whoami', '%PATH%', 'a"b', 'a\nb', 'a|b']) {
    assert.throws(() => invocation('az', [input], 'win32', null), /Unsafe character/);
  }
  assert.deepEqual(invocation('kubectl', ['get', 'pods'], 'win32'), { file: 'kubectl', args: ['get', 'pods'] });
  assert.deepEqual(invocation('az', ['version'], 'win32', 'C:\\Azure\\python.exe'),
    { file: 'C:\\Azure\\python.exe', args: ['-IBm', 'azure.cli', 'version'], env: { AZ_INSTALLER: 'MSI' } });
});

test('exported command diagnostics identify failure classes without retaining stderr', () => {
  const error = new CommandError('COMMAND_FAILED', 'Command failed.', { stderr: 'Forbidden DO_NOT_EXPORT', exitCode: 1 });
  const failure = commandFailure(error);
  assert.equal(failure.code, 'FORBIDDEN');
  assert.ok(!JSON.stringify(failure).includes('DO_NOT_EXPORT'));
});
