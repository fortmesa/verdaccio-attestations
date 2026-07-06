'use strict';

// Installs and caches real npm (8 through whatever "latest" resolves to
// today) and real yarn classic (1.x) binaries on demand, for tests that need
// to drive an actual client CLI against a throwaway registry instead of
// simulating its wire protocol with raw fetch() calls. Yarn Berry (4.x)
// doesn't need anything from here -- it's already corepack-managed via each
// throwaway project's own `packageManager` field.
//
// This file is intentionally duplicated identically across
// fm-npmjs/test/, verdaccio-attestations/test/, and
// verdaccio-security-filter/test/ -- same convention as .prettierrc/
// .yarnrc.yml being copied across the plugin repos: each repo's test suite
// is fully standalone, no shared internal package.

const {execFileSync} = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

// One major version per npm release line actually in wide use today --
// protocol-relevant behavior changes at major boundaries (e.g. npm 7+'s
// bulk-advisory audit vs npm 6's now-removed classic audit), not patches.
const NPM_VERSIONS = ['8', '9', '10', '11'];

const CACHE_ROOT = path.join(os.tmpdir(), 'fm-npmjs-cli-matrix-cache');

function ensureInstalled(cacheDir, spec, binRelPath) {
  const binPath = path.join(cacheDir, binRelPath);
  if (fs.existsSync(binPath)) return binPath;
  fs.mkdirSync(cacheDir, {recursive: true});
  execFileSync(
    process.platform === 'win32' ? 'npm.cmd' : 'npm',
    [
      'install',
      '--prefix',
      cacheDir,
      spec,
      '--silent',
      '--no-audit',
      '--no-fund',
    ],
    {stdio: 'pipe'},
  );
  if (!fs.existsSync(binPath)) {
    throw new Error(
      `expected ${spec} to install a binary at ${binPath}, but it didn't`,
    );
  }
  return binPath;
}

// Returns an absolute path to that major version's npm-cli.js entry point --
// invoke via `node <path> <args>`, not directly (no shebang reliance, works
// identically on every platform).
function getNpmBinary(majorVersion) {
  const cacheDir = path.join(CACHE_ROOT, `npm-${majorVersion}`);
  return ensureInstalled(
    cacheDir,
    `npm@${majorVersion}`,
    path.join('node_modules', 'npm', 'bin', 'npm-cli.js'),
  );
}

function getYarnClassicBinary() {
  const cacheDir = path.join(CACHE_ROOT, 'yarn-classic');
  return ensureInstalled(
    cacheDir,
    'yarn@1.22.22',
    path.join('node_modules', 'yarn', 'bin', 'yarn.js'),
  );
}

// Runs `node <entryJs> ...args` in `cwd`, with `env` merged over the
// current process env (so a caller can point registry/auth config at a
// throwaway registry via env vars without touching global config).
// Returns {status, stdout, stderr} instead of throwing on a non-zero exit --
// callers assert on `status` themselves, since "the CLI exited non-zero" is
// itself sometimes the exact behavior under test (e.g. a rejected publish).
function runNode(entryJs, args, {cwd, env = {}}) {
  const result = require('node:child_process').spawnSync(
    process.execPath,
    [entryJs, ...args],
    {
      cwd,
      env: {...process.env, ...env},
      encoding: 'utf8',
    },
  );
  return {
    status: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

module.exports = {NPM_VERSIONS, getNpmBinary, getYarnClassicBinary, runNode};
