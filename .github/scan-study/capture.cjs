'use strict';

// Study-only observation of the Action's existing CLI spawn. No launch changes.
const childProcess = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { syncBuiltinESMExports } = require('node:module');
const originalSpawn = childProcess.spawn;
let sequence = 0;

function secretForms(...environments) {
  const values = new Set();
  for (const environment of environments) {
    for (const name of ['OPENAI_API_KEY', 'CODEX_API_KEY', 'GITHUB_TOKEN']) {
      const secret = environment && environment[name];
      if (typeof secret !== 'string' || !secret) continue;
      const forms = [secret, Buffer.from(secret).toString('base64'),
        Buffer.from(secret).toString('base64url'), encodeURIComponent(secret),
        encodeURI(secret), new URLSearchParams({ v: secret }).toString().slice(2),
        JSON.stringify(secret).slice(1, -1)];
      for (const form of forms) {
        values.add(form);
        values.add(form.replace(/%[0-9A-F]{2}/g, match => match.toLowerCase()));
      }
    }
  }
  return [...values].sort((left, right) => right.length - left.length);
}

childProcess.spawn = function observedSpawn(command, args, options) {
  // Preserve thrown errors, return identity, arguments, options and environment.
  const child = Reflect.apply(originalSpawn, this, arguments);
  try {
    if (!process.env.STUDY_OUTPUT_DIR || !Array.isArray(args)) return child;
    const argv = [String(command), ...args.map(String)];
    const cliIndex = argv.findIndex(value => value.replaceAll('\\', '/').endsWith('/bin/codex-security.mjs'));
    if (cliIndex < 0 || argv[cliIndex + 1] !== 'scan') return child;
    const forms = secretForms(process.env, options && options.env);
    let redactions = 0;
    function redact(text) {
      for (const secret of forms) {
        const pieces = text.split(secret);
        redactions += pieces.length - 1;
        text = pieces.join('[REDACTED]');
      }
      return text;
    }
    const directory = path.join(process.env.STUDY_OUTPUT_DIR, 'capture');
    const name = `scan-${process.pid}-${++sequence}`;
    const startedAt = new Date().toISOString();
    const started = process.hrtime.bigint();
    const buffers = { stdout: [], stderr: [] };
    let observationFailed = false;
    const save = (suffix, contents) => {
      try {
        fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
        fs.writeFileSync(path.join(directory, name + suffix), contents, { mode: 0o600 });
      } catch { observationFailed = true; }
    };
    save('.invocation.json', redact(JSON.stringify({ started_at: startedAt, argv }, null, 2)) + '\n');
    for (const channel of ['stdout', 'stderr']) {
      child[channel]?.on('data', chunk => {
        try { buffers[channel].push(Buffer.isBuffer(chunk) ? Buffer.from(chunk) : Buffer.from(String(chunk))); }
        catch { observationFailed = true; }
      });
    }
    child.on('close', (exitCode, signal) => {
      try {
        // Redact after buffering so credentials split across stream chunks match.
        for (const channel of ['stdout', 'stderr']) {
          save(`.${channel}.txt`, redact(Buffer.concat(buffers[channel]).toString('utf8')));
        }
        const metadata = { started_at: startedAt, completed_at: new Date().toISOString(),
          duration_ms: Number(process.hrtime.bigint() - started) / 1e6,
          exit_code: exitCode, signal,
          redaction_count: redactions, observation_failed: observationFailed,
          stdout_file: `${name}.stdout.txt`, stderr_file: `${name}.stderr.txt` };
        save('.process.json', JSON.stringify(metadata, null, 2) + '\n');
      } catch { /* Observation must never determine the scan result. */ }
    });
  } catch { /* Observation must never determine the scan result. */ }
  return child;
};
// Also cover an Action bundle using named imports from node:child_process.
syncBuiltinESMExports();
