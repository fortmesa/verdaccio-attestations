'use strict';

// Drives REAL npm (8/9/10/11) and REAL yarn (classic 1.x, berry 4.x) client
// binaries against a real running verdaccio process with THIS plugin's
// current local code loaded (via a symlink into a throwaway node_modules --
// see setupPluginSymlink() below), not a stale last-published version and
// not hand-constructed like test/smoke.js does. Every scenario below runs
// against EVERY client variant, not just one -- a client's own quirks
// (exact request shape, error/exit-code handling, whether it chokes on an
// unfamiliar dist.attestations field) can differ per major version, and
// only happen to be caught by testing all of them, not just the newest.
//
// Run with:
//   yarn install && node test/cli-real.js
// (separate from `yarn test` -- this installs 4 extra npm versions + yarn
// classic on first run, caching them under the OS tmp dir.)

const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const {spawn, spawnSync} = require('node:child_process');
const {
  NPM_VERSIONS,
  getNpmBinary,
  getYarnClassicBinary,
  runNode,
} = require('./cli-matrix');

const PLUGIN_ROOT = path.join(__dirname, '..');
const FIXTURES_DIR = path.join(__dirname, 'fixtures');
const WORKDIR = fs.mkdtempSync(
  path.join(os.tmpdir(), 'attestations-cli-real-'),
);
const STORAGE_DIR = path.join(WORKDIR, 'storage');
const HTPASSWD_FILE = path.join(WORKDIR, 'htpasswd');
const CONFIG_FILE = path.join(WORKDIR, 'config.yaml');
const PLUGINS_DIR = path.join(WORKDIR, 'plugins-node_modules');
const REGISTRY_URL = 'http://127.0.0.1:4880';

// Mixed into every package name this file publishes (except @actions/core,
// tied to the real fixture) -- npm/yarn clients cache a tarball by
// name+version in a persistent, cross-run local cache, on the reasonable
// general assumption that a given name+version is immutable content.
// Reusing the same literal names across repeated runs of this file (each
// against a fresh, unrelated throwaway registry) defeats that assumption
// and serves stale cached content instead of actually fetching from the
// current run's server.
const RUN_ID = crypto.randomBytes(4).toString('hex');

let token; // set once in main(), read by every client factory below

let passed = 0;
const results = [];
async function check(name, fn) {
  try {
    await fn();
    passed += 1;
    results.push(`PASS: ${name}`);
  } catch (err) {
    results.push(`FAIL: ${name}`);
    results.push(err.stack || err.message);
  }
}

// Symlinks this repo's own root into a throwaway node_modules/@fortmesa/
// so Verdaccio's real require()-based plugin loader finds the CURRENT
// local code -- Node resolves a symlinked module's own require() calls
// against its real (target) path, so this plugin's already-installed own
// node_modules (body-parser, minimatch, sigstore, ...) resolve normally.
function setupPluginSymlink() {
  const scopeDir = path.join(PLUGINS_DIR, '@fortmesa');
  fs.mkdirSync(scopeDir, {recursive: true});
  fs.symlinkSync(
    PLUGIN_ROOT,
    path.join(scopeDir, 'verdaccio-attestations'),
    'dir',
  );
}

async function waitForUp(url, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch {
      // not up yet
    }
    await new Promise(r => setTimeout(r, 200));
  }
  throw new Error(`verdaccio never came up at ${url}`);
}

function startVerdaccio(configPath) {
  const bin = path.join(PLUGIN_ROOT, 'node_modules', '.bin', 'verdaccio');
  const proc = spawn(bin, ['--config', configPath, '--listen', '4880'], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  proc.stdout.on('data', d => (output += d));
  proc.stderr.on('data', d => (output += d));
  proc.getOutput = () => output;
  return proc;
}

async function registerUser(username) {
  const res = await fetch(
    `${REGISTRY_URL}/-/user/org.couchdb.user:${username}`,
    {
      method: 'PUT',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify({
        name: username,
        password: crypto.randomBytes(16).toString('hex'),
        type: 'user',
        roles: [],
        date: new Date(0).toISOString(),
      }),
    },
  );
  const body = await res.json();
  if (!body.token)
    throw new Error(`user registration failed: ${JSON.stringify(body)}`);
  return body.token;
}

function makeProjectDir(name, version, deps) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'proj-'));
  fs.writeFileSync(
    path.join(dir, 'package.json'),
    JSON.stringify({name, version, main: 'index.js', dependencies: deps ?? {}}),
  );
  fs.writeFileSync(
    path.join(dir, 'index.js'),
    `module.exports = ${JSON.stringify({marker: name})};\n`,
  );
  return dir;
}

function writeNpmrc(dir) {
  fs.writeFileSync(
    path.join(dir, '.npmrc'),
    [
      `registry=${REGISTRY_URL}/`,
      `//127.0.0.1:4880/:_authToken=${token}`,
      'always-auth=true',
    ].join('\n') + '\n',
  );
}

function writeYarnBerryRc(dir) {
  fs.writeFileSync(
    path.join(dir, '.yarnrc.yml'),
    [
      'nodeLinker: node-modules',
      `npmRegistryServer: '${REGISTRY_URL}'`,
      'npmAlwaysAuth: true',
      `npmAuthToken: '${token}'`,
      'unsafeHttpWhitelist:',
      '  - 127.0.0.1',
      'npmPreapprovedPackages:',
      "  - 'cli-real-*'",
      "  - '@actions/*'",
    ].join('\n') + '\n',
  );
  fs.writeFileSync(path.join(dir, 'yarn.lock'), '');
}

function setYarnBerryPackageManager(dir) {
  const pkgJsonPath = path.join(dir, 'package.json');
  const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
  pkgJson.packageManager = 'yarn@4.17.0';
  fs.writeFileSync(pkgJsonPath, JSON.stringify(pkgJson));
}

// --- one client object per variant, same {name, setup, publish, install}
// shape regardless of which real binary/config format it needs underneath,
// so every scenario below can just loop over ALL of them. ---

function makeNpmClient(majorVersion) {
  const bin = getNpmBinary(majorVersion);
  const opts = dir => ({
    cwd: dir,
    env: {npm_config_userconfig: path.join(dir, '.npmrc')},
  });
  return {
    name: `npm@${majorVersion}`,
    majorVersion,
    setup: writeNpmrc,
    publish: dir =>
      runNode(bin, ['publish', '--registry', REGISTRY_URL], opts(dir)),
    install: dir =>
      runNode(bin, ['install', '--registry', REGISTRY_URL], opts(dir)),
    auditSignatures: dir =>
      runNode(
        bin,
        ['audit', 'signatures', '--registry', REGISTRY_URL],
        opts(dir),
      ),
  };
}

function makeYarnClassicClient() {
  const bin = getYarnClassicBinary();
  return {
    name: 'yarn classic (1.x)',
    setup: writeNpmrc, // yarn classic reads the same .npmrc format
    publish: dir => {
      // yarn classic's `publish` always BUMPS the version via --new-version
      // before publishing -- reading the target version back out of the
      // directory's own package.json (rather than hardcoding one) avoids
      // silently re-bumping to the wrong version if a future test ever
      // publishes more than one version of the same package via this client.
      const {version} = JSON.parse(
        fs.readFileSync(path.join(dir, 'package.json'), 'utf8'),
      );
      return runNode(
        bin,
        [
          'publish',
          '--registry',
          REGISTRY_URL,
          '--new-version',
          version,
          '--no-git-tag-version',
        ],
        {cwd: dir},
      );
    },
    install: dir =>
      runNode(bin, ['install', '--registry', REGISTRY_URL], {cwd: dir}),
  };
}

function makeYarnBerryClient() {
  return {
    name: 'yarn berry (4.x)',
    setup: writeYarnBerryRc,
    publish(dir) {
      setYarnBerryPackageManager(dir);
      const pre = spawnSync('yarn', ['install'], {cwd: dir, encoding: 'utf8'});
      if (pre.status !== 0) return pre;
      return spawnSync('yarn', ['npm', 'publish'], {
        cwd: dir,
        encoding: 'utf8',
      });
    },
    install(dir) {
      setYarnBerryPackageManager(dir);
      return spawnSync('yarn', ['install'], {cwd: dir, encoding: 'utf8'});
    },
  };
}

// Publishing a REAL, verifiable provenance attestation requires a genuine
// Sigstore/Fulcio keyless-signing flow tied to a real CI OIDC identity --
// infeasible to reproduce with a local npm/yarn CLI in this sandbox (there's
// no real GitHub Actions environment to request a token from). Seeding the
// one real captured fixture (@actions/core@3.0.1, fetched from the real npm
// registry earlier and checked into test/fixtures/) via a raw publish
// request is the only feasible way to get a genuinely-verified attestation
// into the registry -- equivalent to what a real `npm publish --provenance`
// would send, just constructed by hand instead of by a live CI-signed
// client. Every real client variant then independently INSTALLS it below,
// which is the part that actually varies per client (does dist.attestations
// -- a field none of these clients know about -- break parsing on some
// older major version?).
// One request on a new connection (agent: false). The CLI checks run each
// client with spawnSync, and only microtasks run between them, so a pooled
// fetch() connection from before them can have been closed by Verdaccio
// without this process noticing. fetch() then writes to the dead socket and
// fails with "other side closed" before the request reaches Verdaccio.
function registryRequest(method, url, {headers = {}, body} = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(url, {method, headers, agent: false}, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('error', reject);
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve({
          ok: res.statusCode >= 200 && res.statusCode < 300,
          status: res.statusCode,
          text: async () => text,
          json: async () => JSON.parse(text),
        });
      });
    });
    req.on('error', reject);
    req.end(body);
  });
}

async function seedRealAttestedPackage() {
  const tarballBuf = fs.readFileSync(
    path.join(FIXTURES_DIR, 'actions-core-3.0.1.tgz'),
  );
  const integrity =
    'sha512-' + crypto.createHash('sha512').update(tarballBuf).digest('base64');
  const fixture = JSON.parse(
    fs.readFileSync(
      path.join(FIXTURES_DIR, 'actions-core-3.0.1-attestations.json'),
      'utf8',
    ),
  );
  const provenance = fixture.attestations.find(a =>
    a.predicateType.includes('slsa.dev'),
  );

  const tarballFilename = 'actions-core-3.0.1.tgz';
  const body = {
    _id: '@actions/core',
    name: '@actions/core',
    description: '',
    'dist-tags': {latest: '3.0.1'},
    versions: {
      '3.0.1': {
        name: '@actions/core',
        version: '3.0.1',
        dist: {
          integrity,
          shasum: crypto.createHash('sha1').update(tarballBuf).digest('hex'),
          tarball: `${REGISTRY_URL}/@actions/core/-/${tarballFilename}`,
        },
      },
    },
    time: {'3.0.1': new Date().toISOString()},
    _attachments: {
      [tarballFilename]: {
        content_type: 'application/octet-stream',
        data: tarballBuf.toString('base64'),
        length: tarballBuf.length,
      },
      'actions-core-3.0.1.sigstore': {
        content_type: 'application/json',
        data: JSON.stringify(provenance.bundle),
        length: 0,
      },
    },
  };
  const res = await registryRequest(
    'PUT',
    `${REGISTRY_URL}/${encodeURIComponent('@actions/core')}`,
    {
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(body),
    },
  );
  if (!res.ok)
    throw new Error(
      `seeding the real attested fixture failed: ${res.status} ${await res.text()}`,
    );

  const packument = await (
    await registryRequest(
      'GET',
      `${REGISTRY_URL}/${encodeURIComponent('@actions/core')}`,
      {headers: {authorization: `Bearer ${token}`}},
    )
  ).json();
  const verified = packument.versions?.['3.0.1']?.dist?.attestations?.verified;
  if (verified !== true) {
    throw new Error(
      `expected the real fixture to verify as true, got: ${JSON.stringify(packument.versions?.['3.0.1']?.dist?.attestations)}`,
    );
  }
}

// Publishes the real, legitimately-published @actions/core@1.0.0 (fetched
// from the real npm registry, no attestation attached) -- this is the
// "blocked, strategy: replace" version in the config above. Real content,
// distinct from 3.0.1's, and (crucially for the replace test below) its own
// internal package.json really does say "1.0.0" -- so if a client installs
// it and *doesn't* get substituted, that's directly observable.
async function seedUnattestedOldVersion() {
  const tarballBuf = fs.readFileSync(
    path.join(FIXTURES_DIR, 'actions-core-1.0.0.tgz'),
  );
  const integrity =
    'sha512-' + crypto.createHash('sha512').update(tarballBuf).digest('base64');
  const tarballFilename = 'actions-core-1.0.0.tgz';
  const body = {
    name: '@actions/core',
    description: '',
    versions: {
      '1.0.0': {
        name: '@actions/core',
        version: '1.0.0',
        dist: {
          integrity,
          shasum: crypto.createHash('sha1').update(tarballBuf).digest('hex'),
          tarball: `${REGISTRY_URL}/@actions/core/-/${tarballFilename}`,
        },
      },
    },
    time: {'1.0.0': new Date().toISOString()},
    _attachments: {
      [tarballFilename]: {
        content_type: 'application/octet-stream',
        data: tarballBuf.toString('base64'),
        length: tarballBuf.length,
      },
    },
  };
  const res = await registryRequest(
    'PUT',
    `${REGISTRY_URL}/${encodeURIComponent('@actions/core')}`,
    {
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(body),
    },
  );
  if (!res.ok)
    throw new Error(
      `seeding the unattested 1.0.0 fixture failed: ${res.status} ${await res.text()}`,
    );
}

// Real, end-to-end confirmation of the storage.localStorage fix: a verdict
// resolved via filter_metadata()'s inline fetchUpstream path (NOT a
// same-request local publish -- seedRealAttestedPackage() above never
// exercises this, since it embeds dist.attestations.verified directly via
// a raw PUT) must actually survive a real pod restart, not just an
// in-memory cache within one process's lifetime. This is the exact
// scenario that surfaced the original addTarball/getTarball recursive-loop
// bug this session -- a real uplink to registry.npmjs.org, a real npm
// client, and a genuine second Verdaccio PROCESS (not just a second
// request) reusing the same storage directory.
async function runStoragePersistencePhase() {
  const port = 4881;
  const registryUrl = `http://127.0.0.1:${port}`;
  const workdir = fs.mkdtempSync(
    path.join(os.tmpdir(), 'attestations-storage-persistence-'),
  );
  const storageDir = path.join(workdir, 'storage');
  const htpasswdFile = path.join(workdir, 'htpasswd');
  const configFile = path.join(workdir, 'config.yaml');
  // The restarted process runs with fetchUpstream off, so the only way it
  // can serve the version is from the verdict the first process stored.
  const restartConfigFile = path.join(workdir, 'config.restart.yaml');
  const pluginsDir = path.join(workdir, 'plugins-node_modules');

  const scopeDir = path.join(pluginsDir, '@fortmesa');
  fs.mkdirSync(scopeDir, {recursive: true});
  fs.symlinkSync(
    PLUGIN_ROOT,
    path.join(scopeDir, 'verdaccio-attestations'),
    'dir',
  );

  const makeConfig = fetchUpstream => `
storage: ${storageDir}
plugins: ${pluginsDir}

uplinks:
  npmjs:
    url: https://registry.npmjs.org/

auth:
  htpasswd:
    file: ${htpasswdFile}
    max_users: 1000

packages:
  '@actions/*':
    access: $all
    publish: $all
    proxy: npmjs
  '**':
    access: $all
    publish: $all
    proxy: npmjs

filters:
  '@fortmesa/verdaccio-attestations':
    fetchUpstream: ${fetchUpstream}
    block:
      - '@actions/core':
          versions: '3.0.1'
          strategy: remove

middlewares:
  '@fortmesa/verdaccio-attestations': {}

log:
  type: stdout
  format: pretty
  level: warn
`;
  fs.mkdirSync(path.dirname(htpasswdFile), {recursive: true});
  fs.writeFileSync(htpasswdFile, '');
  fs.mkdirSync(storageDir, {recursive: true});
  fs.writeFileSync(configFile, makeConfig(true));
  fs.writeFileSync(restartConfigFile, makeConfig(false));

  function startVerdaccioOnPort(cfg) {
    const bin = path.join(PLUGIN_ROOT, 'node_modules', '.bin', 'verdaccio');
    const proc = spawn(bin, ['--config', cfg, '--listen', String(port)], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    proc.stdout.on('data', d => (output += d));
    proc.stderr.on('data', d => (output += d));
    proc.getOutput = () => output;
    return proc;
  }

  async function waitForUpOnPort() {
    const deadline = Date.now() + 20000;
    while (Date.now() < deadline) {
      try {
        const res = await fetch(`${registryUrl}/-/ping`);
        if (res.ok) return;
      } catch {
        // not up yet
      }
      await new Promise(r => setTimeout(r, 200));
    }
    throw new Error(`verdaccio never came up at ${registryUrl}`);
  }

  async function registerUserOnPort(username) {
    const res = await fetch(
      `${registryUrl}/-/user/org.couchdb.user:${username}`,
      {
        method: 'PUT',
        headers: {'content-type': 'application/json'},
        body: JSON.stringify({
          name: username,
          password: crypto.randomBytes(16).toString('hex'),
          type: 'user',
          roles: [],
          date: new Date(0).toISOString(),
        }),
      },
    );
    const body = await res.json();
    if (!body.token)
      throw new Error(`user registration failed: ${JSON.stringify(body)}`);
    return body.token;
  }

  // A real, authenticated identity, not anonymous -- with no
  // verdaccio-offline-enforcer config present at all, an ANONYMOUS request
  // defaults to offline-restricted (enforceForAnonymous: true, matching
  // offline-enforcer's own documented default), which would make
  // fetchUpstream always effectively false regardless of config and defeat
  // the actual point of this phase. A real developer's own install is
  // authenticated in practice anyway.
  let token;

  function installConsumer() {
    const npmBin = getNpmBinary('11');
    const dir = fs.mkdtempSync(
      path.join(os.tmpdir(), 'storage-persistence-proj-'),
    );
    fs.writeFileSync(
      path.join(dir, 'package.json'),
      JSON.stringify({
        name: 'consumer',
        version: '1.0.0',
        dependencies: {'@actions/core': '3.0.1'},
      }),
    );
    fs.writeFileSync(
      path.join(dir, '.npmrc'),
      [
        `registry=${registryUrl}/`,
        `//127.0.0.1:${port}/:_authToken=${token}`,
        'always-auth=true',
      ].join('\n') + '\n',
    );
    return runNode(npmBin, ['install', '--registry', registryUrl], {
      cwd: dir,
      env: {npm_config_userconfig: path.join(dir, '.npmrc')},
    });
  }

  let proc = startVerdaccioOnPort(configFile);
  try {
    await waitForUpOnPort();
    token = await registerUserOnPort('storage-persistence-tester');

    // filter_metadata() fetches and verifies a never-seen version inline,
    // so the very first install already succeeds.
    await check(
      'storage.localStorage persistence: first install of a proxied, never-locally-published version is verified inline and succeeds',
      () => {
        const install = installConsumer();
        assert.equal(
          install.status,
          0,
          `install failed:\n${install.stdout}\n${install.stderr}`,
        );
      },
    );

    await check(
      'storage.localStorage persistence: same process, a second install succeeds from the cached verdict',
      () => {
        const install = installConsumer();
        assert.equal(
          install.status,
          0,
          `install failed:\n${install.stdout}\n${install.stderr}`,
        );
      },
    );
  } finally {
    if (results.some(r => r.startsWith('FAIL'))) {
      console.error('\n--- verdaccio process output (phase 1) ---');
      console.error(proc.getOutput());
    }
    proc.kill();
    await new Promise(r => setTimeout(r, 500)); // let the port actually free up
  }

  // The actual point of this phase: a FRESH Verdaccio PROCESS, same storage
  // directory -- simulates a pod restart. Before the storage.localStorage
  // fix, the verdict computed above never actually reached disk (silently
  // caught, logged, and lost). With fetchUpstream off in this process, the
  // install can only succeed if that stored verdict is found.
  proc = startVerdaccioOnPort(restartConfigFile);
  try {
    await waitForUpOnPort();

    await check(
      'storage.localStorage persistence: a genuinely NEW Verdaccio process (simulated pod restart) with fetchUpstream off installs from the persisted verdict alone',
      () => {
        const install = installConsumer();
        assert.equal(
          install.status,
          0,
          `install must succeed on the very first request after a restart -- if this fails, verdict persistence did not survive the restart:\n${install.stdout}\n${install.stderr}`,
        );
      },
    );
  } finally {
    proc.kill();
    fs.rmSync(workdir, {recursive: true, force: true});
  }
}

async function main() {
  setupPluginSymlink();

  const config = `
storage: ${STORAGE_DIR}
plugins: ${PLUGINS_DIR}

auth:
  htpasswd:
    file: ${HTPASSWD_FILE}
    max_users: 1000

packages:
  '**':
    access: $authenticated
    publish: $authenticated

filters:
  '@fortmesa/verdaccio-attestations':
    fetchUpstream: false
    block:
      - '@blocked/*'
      - '@actions/core':
          strategy: replace

middlewares:
  '@fortmesa/verdaccio-attestations': {}

log:
  type: stdout
  format: pretty
  level: warn
`;
  fs.mkdirSync(path.dirname(HTPASSWD_FILE), {recursive: true});
  fs.writeFileSync(HTPASSWD_FILE, '');
  fs.mkdirSync(STORAGE_DIR, {recursive: true});
  fs.writeFileSync(CONFIG_FILE, config);

  const proc = startVerdaccio(CONFIG_FILE);
  try {
    await waitForUp(`${REGISTRY_URL}/-/ping`);
    token = await registerUser('cli-real-tester');

    const clients = [
      ...NPM_VERSIONS.map(makeNpmClient),
      makeYarnClassicClient(),
      makeYarnBerryClient(),
    ];

    // === plugin loading via Verdaccio's own real loader ===
    await check(
      'verdaccio boots with the current local plugin code loaded via its own loader',
      async () => {
        const res = await fetch(`${REGISTRY_URL}/-/ping`);
        assert.equal(res.status, 200);
      },
    );

    // === every client: plain publish + install round-trip ===
    for (const client of clients) {
      await check(
        `${client.name}: real publish + real install round-trip`,
        () => {
          const slug = client.name.replace(/[^a-z0-9]+/gi, '-');
          const pkgName = `cli-real-${RUN_ID}-${slug}-attest-pkg`;
          const pubDir = makeProjectDir(pkgName, '1.0.0');
          client.setup(pubDir);
          const publish = client.publish(pubDir);
          assert.equal(
            publish.status,
            0,
            `publish failed:\n${publish.stdout}\n${publish.stderr}`,
          );

          const installDir = makeProjectDir('consumer', '1.0.0', {
            [pkgName]: '1.0.0',
          });
          client.setup(installDir);
          const install = client.install(installDir);
          assert.equal(
            install.status,
            0,
            `install failed:\n${install.stdout}\n${install.stderr}`,
          );
          const installed = require(
            path.join(installDir, 'node_modules', pkgName, 'index.js'),
          );
          assert.equal(installed.marker, pkgName);
        },
      );
    }

    // === every client: a block:-matched, unattested package is really uninstallable ===
    for (const client of clients) {
      await check(
        `${client.name}: install of a block:-matched, unattested package fails`,
        () => {
          const slug = client.name.replace(/[^a-z0-9]+/gi, '-');
          const pkgName = `unattested-pkg-${RUN_ID}-${slug}`;
          const pubDir = makeProjectDir(`@blocked/${pkgName}`, '1.0.0');
          client.setup(pubDir);
          const publish = client.publish(pubDir);
          assert.equal(
            publish.status,
            0,
            `publish itself should succeed (attestations never rejects a publish): ${publish.stderr}`,
          );

          const installDir = makeProjectDir('consumer', '1.0.0', {
            [`@blocked/${pkgName}`]: '1.0.0',
          });
          client.setup(installDir);
          const install = client.install(installDir);
          assert.notEqual(
            install.status,
            0,
            'a real install must fail for a block:-matched version with no verified attestation',
          );
        },
      );
    }

    // === every client: a REAL verified attestation installs cleanly ===
    // (seeded once via a raw publish request -- see seedRealAttestedPackage()
    // for why a real CLI can't generate this itself locally -- then every
    // client variant independently installs the SAME already-verified
    // version, proving dist.attestations, a field none of these clients
    // know about, doesn't break parsing on any of them.)
    await seedRealAttestedPackage();
    for (const client of clients) {
      await check(
        `${client.name}: install of a real, verified-attestation package succeeds`,
        () => {
          const installDir = makeProjectDir('consumer', '1.0.0', {
            '@actions/core': '3.0.1',
          });
          client.setup(installDir);
          const install = client.install(installDir);
          assert.equal(
            install.status,
            0,
            `install failed:\n${install.stdout}\n${install.stderr}`,
          );
          assert.ok(
            fs.existsSync(
              path.join(
                installDir,
                'node_modules',
                '@actions',
                'core',
                'package.json',
              ),
            ),
            'the real attested package must actually be installed on disk',
          );
        },
      );
    }

    // === npm audit signatures: real end-to-end provenance verification ===
    // (yarn has no equivalent command -- provenance/attestation verification
    // via `audit signatures` is an npm-only feature -- so this loop is
    // npm-only, unlike every other scenario in this file.)
    //
    // The three outcomes below are not this plugin's choice -- they're npm's
    // own version-dependent behavior against the exact same, correctly-served
    // attestation, confirmed by reading pacote's bundled source across
    // versions:
    //   - npm 8 predates `audit signatures` understanding provenance
    //     attestations at all -- it reports the registry has nothing
    //     auditable, regardless of what we serve.
    //   - npm 9 and 10's pacote unconditionally requires a matching
    //     `/-/npm/v1/keys` registry key for ANY attestation
    //     (`if (!attestationRegistryKeys.length) throw EMISSINGSIGNATUREKEY`),
    //     even though a keyless Sigstore/Fulcio provenance bundle (like this
    //     real one) never has a keyid and by design needs no registry key.
    //     This is a genuine npm-side bug -- not fixable from the registry.
    //   - npm 11's pacote fixed it by only requiring a registry key when the
    //     attestation bundle itself carries a non-empty keyid
    //     (`if (attestationKeyIds.length > 0 && !attestationRegistryKeys.length)`),
    //     so it's the first version that can actually succeed here.
    // Asserting these exact outcomes (rather than skipping npm 8/9/10)
    // means a future npm patching this differently, or a regression in our
    // own dist.attestations.url shape, both show up as a failing test here.
    for (const client of clients) {
      if (!client.auditSignatures) continue;
      const npmMajor = Number(client.majorVersion);
      await check(
        `${client.name}: npm audit signatures against a real verified attestation`,
        () => {
          const installDir = makeProjectDir('consumer', '1.0.0', {
            '@actions/core': '3.0.1',
          });
          client.setup(installDir);
          const install = client.install(installDir);
          assert.equal(
            install.status,
            0,
            `install failed:\n${install.stdout}\n${install.stderr}`,
          );
          const audit = client.auditSignatures(installDir);
          if (npmMajor >= 11) {
            assert.equal(
              audit.status,
              0,
              `npm 11+ must cleanly verify a real keyless attestation:\n${audit.stdout}\n${audit.stderr}`,
            );
            assert.match(
              audit.stdout,
              /verified attestation/,
              'npm 11+ must report the package as having a verified attestation',
            );
          } else if (npmMajor >= 9) {
            assert.notEqual(
              audit.status,
              0,
              'npm 9/10 are known to fail here (see comment above) -- a passing result would mean npm changed behavior and this test needs updating',
            );
            assert.match(
              audit.stderr,
              /EMISSINGSIGNATUREKEY/,
              'npm 9/10 must fail with the known, npm-side EMISSINGSIGNATUREKEY bug, not some other error',
            );
          } else {
            assert.notEqual(
              audit.status,
              0,
              'npm 8 predates provenance-attestation-aware audit signatures and must fail',
            );
            assert.match(
              audit.stderr,
              /no dependencies to audit/,
              'npm 8 must fail with its own "unsupported registry" message, not some other error',
            );
          }
        },
      );
    }

    // === every client: strategy: replace substitutes with the real
    // attested version's real content, not just remove ===
    // (@actions/core@1.0.0 is real, unattested, and falls under the
    // strategy: replace rule above. That rule covers every @actions/core
    // version because a substitute must be one the same read gated and
    // verified, so 3.0.1 has to be gated too. The packument keeps the
    // "1.0.0" version key, but its record is copied from the substitute
    // (3.0.1) minus signatures and attestations, so what a client actually
    // downloads and extracts is 3.0.1's real published tarball. Since both
    // are genuine npm-published packages, each tarball's OWN internal
    // package.json still says its own real version -- installing "1.0.0"
    // and finding "3.0.1" baked into the extracted files is direct,
    // unambiguous proof the substitution actually happened, not just that
    // the install succeeded.)
    await seedUnattestedOldVersion();
    for (const client of clients) {
      await check(
        `${client.name}: strategy: replace substitutes the real attested version's real content`,
        () => {
          const installDir = makeProjectDir('consumer', '1.0.0', {
            '@actions/core': '1.0.0',
          });
          client.setup(installDir);
          const install = client.install(installDir);
          assert.equal(
            install.status,
            0,
            `install failed:\n${install.stdout}\n${install.stderr}`,
          );
          const installedPkgJson = JSON.parse(
            fs.readFileSync(
              path.join(
                installDir,
                'node_modules',
                '@actions',
                'core',
                'package.json',
              ),
              'utf8',
            ),
          );
          assert.equal(
            installedPkgJson.version,
            '3.0.1',
            'installing "1.0.0" must yield 3.0.1\'s real substitute content, not 1.0.0\'s own',
          );
        },
      );
    }
  } finally {
    proc.kill();
    if (process.exitCode) {
      console.error('\n--- verdaccio process output ---');
      console.error(proc.getOutput());
    }
    fs.rmSync(WORKDIR, {recursive: true, force: true});
  }

  // Separate Verdaccio instance/port -- needs a real uplink + fetchUpstream:
  // true, which would change behavior for the main suite's other checks
  // above if configured on the same instance.
  await runStoragePersistencePhase();

  console.log(results.join('\n'));
  console.log(`\n${passed} check(s) passed.`);
  if (results.some(r => r.startsWith('FAIL'))) process.exitCode = 1;
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
