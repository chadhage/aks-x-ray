import { spawn } from 'node:child_process';
import { delimiter, dirname, join, resolve } from 'node:path';
import { existsSync } from 'node:fs';

export class CommandError extends Error {
  constructor(code, message, { stderr = '', exitCode = null } = {}) {
    super(message);
    this.name = 'CommandError';
    this.code = code;
    this.stderr = stderr;
    this.exitCode = exitCode;
  }
}

function installedAzurePython() {
  for (const directory of (process.env.PATH ?? '').split(delimiter)) {
    const shim = join(directory.replace(/^"|"$/g, ''), 'az.cmd');
    const python = resolve(dirname(shim), '..', 'python.exe');
    if (existsSync(shim) && existsSync(python)) return python;
  }
  return null;
}

export function invocation(file, args, platform = process.platform, azurePython) {
  if (platform !== 'win32' || file !== 'az') return { file, args };
  const python = azurePython === undefined ? installedAzurePython() : azurePython;
  // Mirror the official MSI shim without a shell so deadlines terminate the actual CLI process.
  if (python) return { file: python, args: ['-IBm', 'azure.cli', ...args], env: { AZ_INSTALLER: 'MSI' } };
  // az.cmd needs a Windows shell. Only literal, metacharacter-free arguments enter it.
  for (const argument of args) {
    if (/[\r\n"&|<>^%!]/.test(argument)) throw new Error('Unsafe character in an Azure CLI argument.');
  }
  const literal = (value) => `'${value.replaceAll("'", "''")}'`;
  const script = `& 'az.cmd' @(${args.map(literal).join(',')}); exit $LASTEXITCODE`;
  const powershell = process.env.SystemRoot
    ? join(process.env.SystemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe') : 'powershell.exe';
  return {
    file: powershell,
    args: ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')]
  };
}

export function commandFailure(error) {
  if (error instanceof SyntaxError) return { code: 'INVALID_JSON', message: 'Command returned malformed JSON. Raw output was not exported.' };
  if (!(error instanceof CommandError)) return { code: 'INVALID_RESPONSE', message: error.message };
  let code = error.code;
  if (/forbidden|authorizationfailed|does not have authorization/i.test(error.stderr)) code = 'FORBIDDEN';
  else if (/unauthorized|az login|expired|authentication/i.test(error.stderr)) code = 'AUTHENTICATION';
  else if (/notfound|not found|could not be found/i.test(error.stderr)) code = 'NOT_FOUND';
  return {
    code, exitCode: error.exitCode,
    message: `${error.message} Raw stderr is not exported; rerun the recorded command locally for detailed diagnostics.`
  };
}

export async function runCommand(file, args, { input, timeoutMs = 30_000, maxBytes = 20 * 1024 * 1024, signal } = {}) {
  if (signal?.aborted) throw new CommandError('ABORTED', `${file} was cancelled before it started.`);
  const resolved = invocation(file, args);
  return new Promise((resolve, reject) => {
    const child = spawn(resolved.file, resolved.args, {
      shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, ...resolved.env, AZURE_EXTENSION_USE_DYNAMIC_INSTALL: 'no', AZURE_CORE_COLLECT_TELEMETRY: 'false' }
    });
    let stdout = '';
    let stderr = '';
    let bytes = 0;
    let failure;
    const timer = setTimeout(() => {
      failure = new CommandError('TIMEOUT', `${file} exceeded its ${timeoutMs} ms command deadline.`);
      child.kill();
    }, timeoutMs);
    const abort = () => {
      failure = new CommandError('ABORTED', `${file} was cancelled.`);
      child.kill();
    };
    signal?.addEventListener('abort', abort, { once: true });
    const append = (type, chunk) => {
      bytes += Buffer.byteLength(chunk, 'utf8');
      if (bytes > maxBytes && !failure) {
        failure = new CommandError('OUTPUT_LIMIT', `${file} exceeded the ${maxBytes} byte response limit.`);
        child.kill();
      }
      if (!failure) {
        if (type === 'stdout') stdout += chunk;
        else stderr += chunk;
      }
    };
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => append('stdout', chunk));
    child.stderr.on('data', (chunk) => append('stderr', chunk));
    child.on('error', (error) => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      reject(new CommandError(error.code ?? 'SPAWN', `Unable to start ${file}: ${error.code ?? 'process error'}.`));
    });
    child.on('close', (exitCode) => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      if (failure) reject(failure);
      else if (exitCode !== 0) reject(new CommandError('COMMAND_FAILED', `${file} exited with code ${exitCode}.`, { stderr, exitCode }));
      else resolve({ stdout, stderr, exitCode });
    });
    child.stdin.on('error', (error) => {
      if (error.code !== 'EPIPE') {
        failure = new CommandError('STDIN', `Unable to send input to ${file}: ${error.code}.`);
        child.kill();
      }
    });
    child.stdin.end(input);
  });
}
