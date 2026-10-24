'use strict';

const assert = require('node:assert/strict');
const {EventEmitter} = require('node:events');
const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const {Readable} = require('node:stream');
const express = require('express');
const {
  Attestations,
  requestContext,
  __resetSharedStateForTests,
} = require('../index.js');
const {
  verifyBundle,
  verifyAttestationsResponse,
  matchesTrustedPublisher,
  sha512Digest,
} = require('../verify.js');
const {loadSigningKeys, normalizeUpstreamKeysResponse} = require('../keys.js');

const SIGNING_KEY_FIXTURE_DIR = path.join(__dirname, 'fixtures/signing-key');

// Simulates "a real, non-offline-restricted request came in" around a
// direct method call (filter_metadata/_handleGetAttestations/etc.) that
// doesn't go through register_middlewares' own Express middleware chain --
// real request handling establishes this itself; a unit test calling a
// plugin method directly has to do it explicitly, or _effectiveFetchUpstream()
// fails closed (no request context = no fetch), same as it would for a
// genuine non-HTTP code path.
function asOnlineRequest(fn) {
  return requestContext.run({offlineRestricted: false}, fn);
}

const NOOP_LOGGER = {warn() {}, error() {}, info() {}, fatal() {}};

const REAL_ATTESTATIONS = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, 'fixtures/actions-core-3.0.1-attestations.json'),
    'utf8',
  ),
);
const REAL_PKG = {
  name: '@actions/core',
  version: '3.0.1',
  integrity:
    'sha512-a6d/Nwahm9fliVGRhdhofo40HjHQasUPusmc7vBfyky+7Z+P2A1J68zyFVaNcEclc/Se+eO595oAr5nwEIoIUA==',
};
// Fresh copies, so a test that tampers with one can't change another's.
function realProvenanceBundle() {
  return structuredClone(
    REAL_ATTESTATIONS.attestations.find(a =>
      a.predicateType.includes('slsa.dev'),
    ).bundle,
  );
}
function realKeyedBundle() {
  return structuredClone(
    REAL_ATTESTATIONS.attestations.find(
      a => !a.predicateType.includes('slsa.dev'),
    ).bundle,
  );
}
// The real @actions/core@3.0.1 tarball, whose sha512 is REAL_PKG.integrity.
// A publish is only verified when its tarball attachment matches
// dist.integrity, so every publish body that should verify carries this.
const REAL_TARBALL_DATA = fs
  .readFileSync(path.join(__dirname, 'fixtures/actions-core-3.0.1.tgz'))
  .toString('base64');

function integrityOf(buffer) {
  return (
    'sha512-' + crypto.createHash('sha512').update(buffer).digest('base64')
  );
}

// What `npm publish --provenance` sends for @actions/core@3.0.1: the tarball
// (base64) and the .sigstore bundle (a raw JSON string, not base64).
function makeRealPublishBody() {
  return {
    name: '@actions/core',
    versions: {
      '3.0.1': {version: '3.0.1', dist: {integrity: REAL_PKG.integrity}},
    },
    _attachments: {
      'core-3.0.1.tgz': {data: REAL_TARBALL_DATA},
      '@actions/core-3.0.1.sigstore': {
        data: JSON.stringify(realProvenanceBundle()),
      },
    },
  };
}

function makeRealPackageInfo() {
  return makePackageInfo('@actions/core', {
    '3.0.1': {version: '3.0.1', dist: {integrity: REAL_PKG.integrity}},
  });
}

// Who the fake auth below and makeFakeReq() say is making the request.
const DEV_USER = {name: 'dev', real_groups: []};

// Stands in for the auth handle register_middlewares() receives.
// allow_publish/allow_access answer the way Verdaccio's own
// can('publish')/can('access') would: allowed, or an error carrying
// denyStatus. config is auth.config (uplinks, getMatchedPackagesSpec,
// https_proxy).
function makeFakeAuth({
  publish = true,
  access = true,
  denyStatus = 403,
  config = {},
} = {}) {
  const deny = () => Object.assign(new Error('denied'), {status: denyStatus});
  return {
    config,
    allow_publish(pkg, user, cb) {
      process.nextTick(() => (publish ? cb(null, true) : cb(deny())));
    },
    allow_access(pkg, user, cb) {
      process.nextTick(() => (access ? cb(null, true) : cb(deny())));
    },
  };
}

// Every package proxies from registry.npmjs.org, the way a default
// Verdaccio config's "**: proxy: npmjs" does.
const NPMJS_PROXY_CONFIG = {
  uplinks: {npmjs: {url: 'https://registry.npmjs.org'}},
  getMatchedPackagesSpec: () => ({proxy: 'npmjs'}),
};

// Mirrors Verdaccio's real addTarball/getTarball/removeTarball contract
// (verified this session against verdaccio/build/lib/local-storage.js and
// publish.js): custom 'error'/'success' events on write, a readable-style
// 'data'/'end'/'error' stream on read, a plain (packageName, filename,
// revision, callback) shape on remove -- not a plain Node stream. This is
// the shape of storage.localStorage specifically (the safe, lower-level
// class), not the top-level Storage object register_middlewares() actually
// receives -- see wrapAsTopLevelStorage() below for the distinction that
// matters to this plugin's own code.
function makeFakeStorage() {
  const files = new Map(); // "pkg\x00filename" -> Buffer
  return {
    files,
    addTarball(packageName, filename) {
      const key = `${packageName}\x00${filename}`;
      const chunks = [];
      const emitter = new EventEmitter();
      emitter.end = data => {
        if (data) chunks.push(data);
      };
      emitter.done = () => {
        files.set(key, Buffer.concat(chunks));
        process.nextTick(() => emitter.emit('success'));
      };
      emitter.abort = () => {};
      return emitter;
    },
    getTarball(packageName, filename) {
      const key = `${packageName}\x00${filename}`;
      const emitter = new EventEmitter();
      process.nextTick(() => {
        const data = files.get(key);
        if (!data) {
          emitter.emit(
            'error',
            Object.assign(new Error('not found'), {
              code: 'ENOENT',
              status: 404,
            }),
          );
          return;
        }
        emitter.emit('data', data);
        emitter.emit('end');
      });
      return emitter;
    },
    removeTarball(packageName, filename, revision, callback) {
      const key = `${packageName}\x00${filename}`;
      process.nextTick(() => {
        if (!files.has(key)) {
          callback(
            Object.assign(new Error('no such file available'), {code: 404}),
          );
          return;
        }
        files.delete(key);
        callback(null);
      });
    },
  };
}

// Minimal fake req for direct _interceptPublish() calls -- needs .protocol
// and .get('host') since dist.attestations.url is built from them (must be
// absolute, see index.js's comment on that field), which a bare {body}
// object doesn't provide the way a real Express req does.
function makeFakeReq(body, remoteUser = DEV_USER) {
  return {
    body,
    remote_user: remoteUser,
    protocol: 'http',
    get: header => (header === 'host' ? 'localhost:4873' : undefined),
  };
}

// Records what _handleGetAttestations() answers.
function makeRecordingRes() {
  return {
    statusCode: undefined,
    body: undefined,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    },
    end() {},
  };
}

// An Express app without the X-Powered-By header.
function makeApp() {
  const app = express();
  app.disable('x-powered-by');
  return app;
}

// Starts app on a free port; the caller closes the returned server.
function listen(app) {
  return new Promise(resolve => {
    const s = app.listen(0, () => resolve(s));
  });
}

// The plugin's own _getLocalStorage() reads storage.localStorage, matching
// the REAL Storage class register_middlewares() actually receives (its own
// addTarball/getTarball must never be used directly -- see index.js's
// comment on _getLocalStorage() for why). Every test that assigns
// plugin._storage or calls register_middlewares() with a fake storage needs
// this wrapping now; the returned localStorage sub-object is still the
// same one makeFakeStorage() produces, so `.files` introspection on it is
// unaffected.
function wrapAsTopLevelStorage(localStorage) {
  return {localStorage};
}

// keyed by "<name>@<version>" -- default throws, since a test that expects
// no upstream call at all (e.g. a locally-stored hit, or fetchUpstream:
// false) should fail loudly if one happens anyway.
function makeFakeFetch(responses) {
  return async url => {
    for (const [key, response] of Object.entries(responses)) {
      if (url.endsWith(key)) return response;
    }
    throw new Error(`unexpected fetch: ${url}`);
  };
}

function makeAttestations(config, overrides = {}) {
  return new Attestations(config, {
    logger: NOOP_LOGGER,
    fetch: overrides.fetch ?? makeFakeFetch({}),
    verdictCache: overrides.verdictCache,
    ...overrides,
  });
}

// _interceptPublish defers its storage write to res.on('finish', ...) (see
// index.js for why -- a brand-new package's first publish has no record in
// storage yet at interception time). This fake res lets tests trigger that
// event on demand instead of needing a real HTTP response cycle.
function makeFakeRes(statusCode = 201) {
  let finishCb;
  return {
    statusCode,
    on(event, cb) {
      if (event === 'finish') finishCb = cb;
    },
    _triggerFinish() {
      finishCb?.();
    },
  };
}

function makePackageInfo(name, versions) {
  const time = {};
  for (const v of Object.keys(versions)) time[v] = '2025-01-01T00:00:00Z';
  return {
    name,
    versions,
    time,
    'dist-tags': {latest: Object.keys(versions).at(-1)},
  };
}

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

async function main() {
  // --- verify.js, against the real @actions/core@3.0.1 bundle ---

  await check(
    'verifyBundle succeeds against a real, unmodified provenance bundle',
    async () => {
      const result = await verifyBundle(REAL_PKG, realProvenanceBundle());
      assert.equal(result.verified, true);
      assert.equal(result.predicateType, 'https://slsa.dev/provenance/v1');
    },
  );

  await check(
    'verifyBundle fails when the version does not match the attested subject',
    async () => {
      const result = await verifyBundle(
        {...REAL_PKG, version: '9.9.9'},
        realProvenanceBundle(),
      );
      assert.equal(result.verified, false);
      assert.match(result.reason, /does not match package/);
    },
  );

  await check(
    'verifyBundle fails when the integrity does not match the attested subject digest',
    async () => {
      const result = await verifyBundle(
        {...REAL_PKG, integrity: integrityOf(Buffer.from('other bytes'))},
        realProvenanceBundle(),
      );
      assert.equal(result.verified, false);
      assert.match(result.reason, /digest does not match/);
    },
  );

  await check(
    "verifyBundle rejects npm's own keyed 'publish attestation' -- not a SLSA provenance predicate",
    async () => {
      const result = await verifyBundle(REAL_PKG, realKeyedBundle());
      assert.equal(result.verified, false);
      assert.match(result.reason, /not a SLSA provenance attestation/);
    },
  );

  // --- trustedPublishers: identity pinning for locally-published packages ---
  // Real bundle's certificate SAN (confirmed via node:crypto's X509Certificate
  // and the real sigstore.verify() call itself, independently):
  // "https://github.com/actions/toolkit/.github/workflows/releases.yml@refs/heads/main"
  const REAL_SAN =
    'https://github.com/actions/toolkit/.github/workflows/releases.yml@refs/heads/main';
  const REAL_ISSUER = 'https://token.actions.githubusercontent.com';

  await check(
    'verifyBundle succeeds when trustedPublishers is configured and the certificate matches one entry',
    async () => {
      const result = await verifyBundle(REAL_PKG, realProvenanceBundle(), {}, [
        {subjectAlternativeName: 'https://github.com/actions/toolkit/**'},
      ]);
      assert.equal(result.verified, true);
    },
  );

  await check(
    'verifyBundle fails when trustedPublishers is configured and the certificate matches no entry, even though the signature is genuinely valid',
    async () => {
      const result = await verifyBundle(REAL_PKG, realProvenanceBundle(), {}, [
        {
          subjectAlternativeName:
            'https://github.com/someone-else/other-repo/**',
        },
      ]);
      assert.equal(result.verified, false);
      assert.match(result.reason, /not in the trusted publisher list/);
    },
  );

  await check(
    'verifyBundle: an issuer-only trustedPublishers entry matches on issuer alone',
    async () => {
      const result = await verifyBundle(REAL_PKG, realProvenanceBundle(), {}, [
        {issuer: REAL_ISSUER},
      ]);
      assert.equal(result.verified, true);
    },
  );

  await check(
    'verifyBundle: an entry with both issuer and subjectAlternativeName requires both to match',
    async () => {
      const wrongIssuer = await verifyBundle(
        REAL_PKG,
        realProvenanceBundle(),
        {},
        [
          {
            issuer: 'https://gitlab.example.com',
            subjectAlternativeName: 'https://github.com/actions/toolkit/**',
          },
        ],
      );
      assert.equal(wrongIssuer.verified, false);

      const bothMatch = await verifyBundle(
        REAL_PKG,
        realProvenanceBundle(),
        {},
        [
          {
            issuer: REAL_ISSUER,
            subjectAlternativeName: 'https://github.com/actions/toolkit/**',
          },
        ],
      );
      assert.equal(bothMatch.verified, true);
    },
  );

  await check(
    'matchesTrustedPublisher: not GitHub-specific -- a non-GitHub-shaped subjectAlternativeName pattern works the same way',
    () => {
      const gitlabIdentity = {
        subjectAlternativeName:
          'https://gitlab.example.com/some-group/some-project//path/to/.gitlab-ci.yml@refs/heads/main',
        extensions: {issuer: 'https://gitlab.example.com'},
      };
      assert.equal(
        matchesTrustedPublisher(gitlabIdentity, [
          {
            subjectAlternativeName:
              'https://gitlab.example.com/some-group/some-project/**',
          },
        ]),
        true,
      );
      assert.equal(
        matchesTrustedPublisher(gitlabIdentity, [
          {subjectAlternativeName: 'https://github.com/**'},
        ]),
        false,
      );
    },
  );

  await check(
    'matchesTrustedPublisher: no identity on the certificate at all never matches',
    () => {
      assert.equal(
        matchesTrustedPublisher(undefined, [{subjectAlternativeName: '**'}]),
        false,
      );
    },
  );

  await check(
    'construction throws loud on a malformed sigstore.trustedPublishers entry',
    () => {
      assert.throws(
        () =>
          makeAttestations({
            sigstore: {trustedPublishers: [{unknownKey: 'x'}]},
          }),
        /unknown key/,
      );
      assert.throws(
        () => makeAttestations({sigstore: {trustedPublishers: [{}]}}),
        /must set at least one of/,
      );
      assert.throws(
        () =>
          makeAttestations({
            sigstore: {trustedPublishers: ['not-an-object']},
          }),
        /must be an object/,
      );
    },
  );

  await check(
    'end-to-end: a local publish is verified when its certificate matches sigstore.trustedPublishers',
    async () => {
      const plugin = makeAttestations({
        sigstore: {
          trustedPublishers: [
            {subjectAlternativeName: 'https://github.com/actions/toolkit/**'},
          ],
        },
      });
      const storage = makeFakeStorage();
      const bundle = realProvenanceBundle();
      const body = {
        versions: {
          '3.0.1': {version: '3.0.1', dist: {integrity: REAL_PKG.integrity}},
        },
        _attachments: {
          'core-3.0.1.tgz': {data: REAL_TARBALL_DATA},
          '@actions/core-3.0.1.sigstore': {
            data: JSON.stringify(bundle), // raw string, matching real npm/Yarn -- NOT base64
          },
        },
      };
      const req = makeFakeReq(body);
      const res = makeFakeRes();
      await plugin._interceptPublish(req, res, '@actions/core');
      res._triggerFinish();
      await plugin.whenAllBackgroundWorkSettles();

      assert.equal(body.versions['3.0.1'].dist.attestations.verified, true);
    },
  );

  await check(
    'end-to-end: a local publish is rejected-as-unverified when its certificate does not match sigstore.trustedPublishers, despite a genuinely valid signature',
    async () => {
      const plugin = makeAttestations({
        sigstore: {
          trustedPublishers: [
            {subjectAlternativeName: 'https://github.com/someone-else/**'},
          ],
        },
      });
      const bundle = realProvenanceBundle();
      const body = {
        versions: {
          '3.0.1': {version: '3.0.1', dist: {integrity: REAL_PKG.integrity}},
        },
        _attachments: {
          'core-3.0.1.tgz': {data: REAL_TARBALL_DATA},
          '@actions/core-3.0.1.sigstore': {
            data: JSON.stringify(bundle), // raw string, matching real npm/Yarn -- NOT base64
          },
        },
      };
      const req = makeFakeReq(body);
      const res = makeFakeRes();
      await plugin._interceptPublish(req, res, '@actions/core');
      res._triggerFinish();
      await plugin.whenAllBackgroundWorkSettles();

      assert.equal(body.versions['3.0.1'].dist.attestations.verified, false);
      assert.match(
        body.versions['3.0.1'].dist.attestations.reason,
        /not in the trusted publisher list/,
      );
    },
  );

  await check(
    'unconfigured (default empty) sigstore.trustedPublishers means no identity check at all -- same as before this feature existed',
    async () => {
      const plugin = makeAttestations({});
      const bundle = realProvenanceBundle();
      const body = {
        versions: {
          '3.0.1': {version: '3.0.1', dist: {integrity: REAL_PKG.integrity}},
        },
        _attachments: {
          'core-3.0.1.tgz': {data: REAL_TARBALL_DATA},
          '@actions/core-3.0.1.sigstore': {
            data: JSON.stringify(bundle), // raw string, matching real npm/Yarn -- NOT base64
          },
        },
      };
      const req = makeFakeReq(body);
      const res = makeFakeRes();
      await plugin._interceptPublish(req, res, '@actions/core');
      res._triggerFinish();
      await plugin.whenAllBackgroundWorkSettles();

      assert.equal(body.versions['3.0.1'].dist.attestations.verified, true);
    },
  );

  await check(
    'verifyAttestationsResponse finds and returns the provenance bundle, not the keyed one that comes first',
    async () => {
      const result = await verifyAttestationsResponse(
        REAL_PKG,
        REAL_ATTESTATIONS,
      );
      assert.equal(result.verified, true);
      assert.deepEqual(
        result.bundle,
        realProvenanceBundle(),
        'must return the bundle that actually verified, not attestations[0]',
      );
    },
  );

  await check(
    'verifyAttestationsResponse reports failure when there are no attestations at all',
    async () => {
      const result = await verifyAttestationsResponse(REAL_PKG, {
        attestations: [],
      });
      assert.equal(result.verified, false);
      assert.match(result.reason, /no attestations present/);
    },
  );

  // --- matching: block:/allow: use real minimatch, same convention Verdaccio's own packages: config uses ---

  await check(
    'verifyBundle: a trust root that cannot be fetched is transient, not a verdict',
    async () => {
      const cache = fs.mkdtempSync(path.join(os.tmpdir(), 'att-tuf-'));
      try {
        const result = await verifyBundle(REAL_PKG, realProvenanceBundle(), {
          tufMirrorURL: 'http://127.0.0.1:1',
          tufCachePath: cache,
        });
        assert.equal(result.verified, false);
        assert.equal(result.transient, true, result.reason);
      } finally {
        fs.rmSync(cache, {recursive: true, force: true});
      }
    },
  );

  await check(
    'verifyBundle: a tampered signature is a definite failure, not transient',
    async () => {
      const bundle = realProvenanceBundle();
      bundle.dsseEnvelope.signatures[0].sig = Buffer.alloc(64, 1).toString(
        'base64',
      );
      const result = await verifyBundle(REAL_PKG, bundle);
      assert.equal(result.verified, false);
      assert.equal(result.transient, undefined, result.reason);
    },
  );

  await check(
    'verifyBundle: an unexpected throw inside verification is returned as transient, never thrown',
    async () => {
      // A non-array trustedPublishers makes the identity check throw after
      // sigstore.verify() succeeds.
      const result = await verifyBundle(
        REAL_PKG,
        realProvenanceBundle(),
        {},
        {},
      );
      assert.equal(result.verified, false);
      assert.equal(result.transient, true);
      assert.match(result.reason, /^verification error:/);
    },
  );

  await check(
    'sha512Digest accepts exactly one sha512 entry and nothing else',
    () => {
      const one = integrityOf(Buffer.from('a'));
      assert.deepEqual(
        sha512Digest(one),
        crypto.createHash('sha512').update('a').digest(),
      );
      assert.ok(sha512Digest(`  ${one}\n`), 'surrounding whitespace is fine');
      const sha1 = `sha1-${crypto.createHash('sha1').update('a').digest('base64')}`;
      for (const bad of [
        `${one} ${integrityOf(Buffer.from('b'))}`,
        `${one} ${sha1}`,
        sha1,
        `${one}?opt`,
        'sha512-a',
        'sha512-',
        '',
        undefined,
        42,
      ]) {
        assert.equal(sha512Digest(bad), null, String(bad));
      }
    },
  );

  await check(
    'verifyBundle rejects an integrity listing a second sha512, even when the first one is the attested digest',
    async () => {
      const result = await verifyBundle(
        {
          ...REAL_PKG,
          integrity: `${REAL_PKG.integrity} ${integrityOf(Buffer.from('other'))}`,
        },
        realProvenanceBundle(),
      );
      assert.equal(result.verified, false);
      assert.equal(
        result.reason,
        'dist.integrity is not a single sha512 digest',
      );
    },
  );

  await check(
    'block: uses real minimatch globs -- a scoped wildcard does not cross an extra "/"',
    async () => {
      const plugin = makeAttestations({block: ['@scope/*']});
      const shallow = makePackageInfo('@scope/pkg', {
        '1.0.0': {version: '1.0.0', dist: {integrity: 'sha512-x'}},
      });
      const deep = makePackageInfo('@scope/deep/pkg', {
        '1.0.0': {version: '1.0.0', dist: {integrity: 'sha512-x'}},
      });
      const shallowResult = await plugin.filter_metadata(shallow);
      const deepResult = await plugin.filter_metadata(deep);
      assert.ok(
        !('1.0.0' in shallowResult.versions),
        '@scope/* must match @scope/pkg',
      );
      assert.ok(
        '1.0.0' in deepResult.versions,
        '@scope/* must NOT match @scope/deep/pkg -- minimatch * does not cross /',
      );
    },
  );

  await check(
    'a block: rule scoped to a semver range only gates matching versions',
    async () => {
      const plugin = makeAttestations({
        block: [{'some-pkg': {versions: '>=2.0.0'}}],
      });
      const pkg = makePackageInfo('some-pkg', {
        '1.0.0': {version: '1.0.0', dist: {integrity: 'sha512-x'}}, // outside the range -- not gated at all
        '2.0.0': {version: '2.0.0', dist: {integrity: 'sha512-x'}}, // inside the range -- gated, unattested
      });
      const result = await plugin.filter_metadata(pkg);
      assert.ok(
        '1.0.0' in result.versions,
        'versions outside the rule range are never gated',
      );
      assert.ok(
        !('2.0.0' in result.versions),
        'versions inside the rule range are gated and blocked when unattested',
      );
    },
  );

  await check(
    'a bare block: rule (no strategy) hard-removes; a rule with strategy: replace substitutes instead',
    async () => {
      const plugin = makeAttestations({
        block: [{'some-pkg': {strategy: 'replace'}}, 'other-pkg'],
      });
      // 0.9.0 is gated by the same rule and already known to be verified.
      plugin._verdictCache.set('some-pkg@0.9.0', {
        verified: true,
        integrity: 'sha512-good',
      });
      const withStrategy = makePackageInfo('some-pkg', {
        '0.9.0': {
          version: '0.9.0',
          dist: {integrity: 'sha512-good', tarball: 'good.tgz'},
        },
        '1.0.0': {version: '1.0.0', dist: {integrity: 'sha512-bad'}},
      });
      const replaced = await plugin.filter_metadata(withStrategy);
      assert.ok('1.0.0' in replaced.versions, 'replaced version keeps its key');
      assert.equal(replaced.versions['1.0.0'].version, '1.0.0');
      assert.equal(replaced.versions['1.0.0'].dist.tarball, 'good.tgz');

      const bare = makePackageInfo('other-pkg', {
        '1.0.0': {version: '1.0.0', dist: {integrity: 'sha512-bad'}},
      });
      const removed = await plugin.filter_metadata(bare);
      assert.ok(
        !('1.0.0' in removed.versions),
        'a bare rule with no strategy hard-removes',
      );
    },
  );

  await check(
    'strategy: replace substitutes only a version this call gated and verified, and strips the copied signatures and attestations',
    async () => {
      const plugin = makeAttestations({
        block: [{'some-pkg': {versions: '>=1.0.0', strategy: 'replace'}}],
      });
      plugin._verdictCache.set('some-pkg@1.1.0', {
        verified: true,
        integrity: 'sha512-good',
      });
      const pkg = makePackageInfo('some-pkg', {
        // Outside the rule's range, so nothing checked it.
        '0.9.0': {version: '0.9.0', dist: {integrity: 'sha512-ungated'}},
        '1.0.0': {version: '1.0.0', dist: {integrity: 'sha512-bad'}},
        '1.1.0': {
          version: '1.1.0',
          dist: {
            integrity: 'sha512-good',
            tarball: 'good.tgz',
            signatures: [{keyid: 'SHA256:x', sig: 'c2ln'}],
            attestations: {url: 'https://registry.example/x', verified: true},
          },
        },
        '1.2.0': {version: '1.2.0', dist: {integrity: 'sha512-bad'}},
      });
      const result = await plugin.filter_metadata(pkg);
      for (const ver of ['1.0.0', '1.2.0']) {
        const replaced = result.versions[ver];
        assert.equal(
          replaced.dist.tarball,
          'good.tgz',
          `${ver} must be replaced by the verified 1.1.0, never the nearer, unchecked 0.9.0`,
        );
        assert.equal(replaced.version, ver);
        assert.equal(replaced.dist.signatures, undefined);
        assert.equal(replaced.dist.attestations, undefined);
      }
      assert.ok(
        result.versions['1.1.0'].dist.signatures,
        'the substitute itself keeps its own signatures',
      );

      const noVerified = makePackageInfo('some-pkg', {
        '0.9.0': {version: '0.9.0', dist: {integrity: 'sha512-ungated'}},
        '1.0.0': {version: '1.0.0', dist: {integrity: 'sha512-bad'}},
      });
      const removed = await plugin.filter_metadata(noVerified);
      assert.ok(
        !('1.0.0' in removed.versions),
        'with no verified substitute the version is removed, not replaced by an unchecked one',
      );
      assert.ok('0.9.0' in removed.versions);
    },
  );

  await check(
    'a non-semver version key under a version-scoped replace rule throws nothing, and the gated versions are still removed',
    async () => {
      // filter_metadata() also removes gated versions when the filter
      // throws, so "nothing thrown" is checked through the error it logs.
      const errors = [];
      const plugin = makeAttestations(
        {block: [{'some-pkg': {versions: '>=1.0.0', strategy: 'replace'}}]},
        {logger: {...NOOP_LOGGER, error: (...args) => errors.push(args)}},
      );
      const pkg = makePackageInfo('some-pkg', {
        '0.5.0': {version: '0.5.0', dist: {integrity: 'sha512-a'}},
        'not-a-version': {version: 'not-a-version', dist: {}},
        '1.0.0': {version: '1.0.0', dist: {integrity: 'sha512-b'}},
      });
      pkg['dist-tags'].latest = '1.0.0';
      const result = await plugin.filter_metadata(pkg);
      assert.deepEqual(errors, []);
      assert.ok(!('1.0.0' in result.versions));
      assert.equal(
        result['dist-tags'].latest,
        '0.5.0',
        'dist-tags are repointed at a valid semver version only',
      );
    },
  );

  // --- filter_metadata: fast tier only, background verification for the rest ---

  await check(
    'filter_metadata: an internal error removes every gated version instead of throwing, and dist-tags move to what is left',
    async () => {
      const plugin = makeAttestations({
        block: [{'some-pkg': {versions: '>=2.0.0'}}],
      });
      plugin._filterMetadata = async () => {
        throw new Error('boom');
      };
      const pkg = makePackageInfo('some-pkg', {
        '1.0.0': {version: '1.0.0', dist: {}},
        '2.0.0': {version: '2.0.0', dist: {}},
      });
      const result = await plugin.filter_metadata(pkg);
      assert.deepEqual(Object.keys(result.versions), ['1.0.0']);
      assert.equal(result['dist-tags'].latest, '1.0.0');
    },
  );

  await check(
    'filter_metadata is a no-op when block: is empty (disabled by default)',
    async () => {
      const plugin = makeAttestations({block: []});
      const pkg = makePackageInfo('left-pad', {
        '1.0.0': {version: '1.0.0', dist: {}},
      });
      const result = await plugin.filter_metadata(pkg);
      assert.ok('1.0.0' in result.versions);
    },
  );

  await check(
    'filter_metadata ignores a packument claiming dist.attestations.verified:true -- the gated version is still blocked',
    async () => {
      const plugin = makeAttestations({block: ['**']});
      const pkg = makePackageInfo('some-pkg', {
        '1.0.0': {
          version: '1.0.0',
          dist: {
            integrity: 'sha512-x',
            attestations: {verified: true, url: '/x'},
          },
        },
      });
      const result = await plugin.filter_metadata(pkg);
      assert.ok(!('1.0.0' in result.versions));
    },
  );

  await check(
    'a publish body that sets dist.attestations.verified:true with no .sigstore does not make a gated version pass',
    async () => {
      const plugin = makeAttestations({block: ['**']});
      plugin._auth = makeFakeAuth();
      plugin._storage = wrapAsTopLevelStorage(makeFakeStorage());
      const body = {
        name: 'some-pkg',
        versions: {
          '1.0.0': {
            version: '1.0.0',
            dist: {
              integrity: 'sha512-x',
              attestations: {verified: true, url: '/x'},
              signatures: [{keyid: 'SHA256:x', sig: 'c2ln'}],
            },
          },
        },
        _attachments: {'some-pkg-1.0.0.tgz': {data: 'ZmFrZQ=='}},
      };
      const res = makeFakeRes(201);
      await plugin._handlePublish(makeFakeReq(body), res, 'some-pkg');
      res._triggerFinish();
      await plugin.whenAllBackgroundWorkSettles();

      assert.equal(body.versions['1.0.0'].dist.attestations, undefined);
      assert.equal(body.versions['1.0.0'].dist.signatures, undefined);
      assert.equal(plugin._verdictCache.size, 0);
      // What Verdaccio stores is the body as this plugin left it.
      const result = await plugin.filter_metadata(
        makePackageInfo('some-pkg', structuredClone(body.versions)),
      );
      assert.ok(!('1.0.0' in result.versions));
    },
  );

  await check(
    'allow: overrides block: for a matching package name',
    async () => {
      const plugin = makeAttestations({block: ['**'], allow: ['neversigned']});
      const pkg = makePackageInfo('neversigned', {
        '1.0.0': {version: '1.0.0', dist: {integrity: 'sha512-x'}},
      });
      const result = await plugin.filter_metadata(pkg);
      assert.ok(
        '1.0.0' in result.versions,
        'allow-listed package must never be blocked',
      );
    },
  );

  await check(
    'a never-before-seen version is resolved for real on the very first read, not wrongly blocked while a background check catches up',
    async () => {
      let fetchCalls = 0;
      const plugin = makeAttestations(
        {block: ['**'], fetchUpstream: true},
        {
          fetch: async () => {
            fetchCalls += 1;
            return {ok: true, json: async () => REAL_ATTESTATIONS};
          },
        },
      );
      plugin._storage = wrapAsTopLevelStorage(makeFakeStorage());
      plugin._auth = makeFakeAuth({config: NPMJS_PROXY_CONFIG});

      const pkg = makePackageInfo('@actions/core', {
        '3.0.1': {version: '3.0.1', dist: {integrity: REAL_PKG.integrity}},
      });

      await asOnlineRequest(async () => {
        const first = await plugin.filter_metadata(structuredClone(pkg));
        assert.ok(
          '3.0.1' in first.versions,
          'the very first read must already reflect the real verdict -- ' +
            'a version that would verify cleanly must never be wrongly ' +
            'blocked just because nothing had checked it yet',
        );
        assert.equal(fetchCalls, 1);

        // A second read must not repeat the upstream fetch -- the fast
        // (cache/storage) tier now has an answer.
        const second = await plugin.filter_metadata(structuredClone(pkg));
        assert.ok('3.0.1' in second.versions);
        assert.equal(fetchCalls, 1);
      });
    },
  );

  await check(
    'a never-before-seen version that fails to verify is blocked on the very first read, not deferred',
    async () => {
      const plugin = makeAttestations(
        {block: ['**'], fetchUpstream: true},
        {
          fetch: async () => ({
            ok: true,
            json: async () => ({attestations: []}),
          }),
        },
      );
      plugin._storage = wrapAsTopLevelStorage(makeFakeStorage());
      plugin._auth = makeFakeAuth({config: NPMJS_PROXY_CONFIG});

      const pkg = makePackageInfo('some-pkg', {
        '1.0.0': {version: '1.0.0', dist: {integrity: 'sha512-a'}},
      });

      await asOnlineRequest(async () => {
        const result = await plugin.filter_metadata(structuredClone(pkg));
        assert.ok(!('1.0.0' in result.versions));
      });
    },
  );

  await check(
    'checking one version never delays another -- both resolve concurrently, not one after another',
    async () => {
      const callOrder = [];
      const plugin = makeAttestations(
        {block: ['**'], fetchUpstream: true},
        {
          fetch: async url => {
            callOrder.push('start:' + url.slice(-20));
            await new Promise(r => setTimeout(r, 20));
            callOrder.push('end:' + url.slice(-20));
            return {ok: true, json: async () => ({attestations: []})};
          },
        },
      );
      plugin._storage = wrapAsTopLevelStorage(makeFakeStorage());
      plugin._auth = makeFakeAuth({config: NPMJS_PROXY_CONFIG});

      const pkg = makePackageInfo('multi-ver-pkg', {
        '1.0.0': {version: '1.0.0', dist: {integrity: 'sha512-a'}},
        '2.0.0': {version: '2.0.0', dist: {integrity: 'sha512-b'}},
      });
      await asOnlineRequest(() => plugin.filter_metadata(pkg));
      // If these ran sequentially, the second fetch could only start after
      // the first's 'end' -- concurrent execution means both starts land
      // before either end.
      assert.deepEqual(
        callOrder.slice(0, 2).map(c => c.split(':')[0]),
        ['start', 'start'],
      );
    },
  );

  await check(
    "the upstream attestation fetch targets this package's own configured proxy uplink, not a hardcoded registry",
    async () => {
      let fetchedUrl;
      const plugin = makeAttestations(
        {block: ['**'], fetchUpstream: true},
        {
          fetch: async url => {
            fetchedUrl = url;
            return {ok: true, json: async () => ({attestations: []})};
          },
        },
      );
      plugin._storage = wrapAsTopLevelStorage(makeFakeStorage());
      plugin._auth = {
        config: {
          uplinks: {
            'internal-mirror': {
              url: 'https://npm-mirror.internal.example.com/',
            },
          },
          getMatchedPackagesSpec: name =>
            name === 'some-pkg' ? {proxy: 'internal-mirror'} : undefined,
        },
      };

      const pkg = makePackageInfo('some-pkg', {
        '1.0.0': {version: '1.0.0', dist: {integrity: 'sha512-a'}},
      });
      await asOnlineRequest(() => plugin.filter_metadata(structuredClone(pkg)));

      assert.ok(
        fetchedUrl.startsWith('https://npm-mirror.internal.example.com'),
        `expected the configured uplink's own host, got: ${fetchedUrl}`,
      );
    },
  );

  await check(
    'a package with no proxy configured triggers no upstream fetch at all, and is blocked',
    async () => {
      let fetchCalls = 0;
      const plugin = makeAttestations(
        {block: ['**'], fetchUpstream: true},
        {
          fetch: async () => {
            fetchCalls += 1;
            return {ok: true, json: async () => REAL_ATTESTATIONS};
          },
        },
      );
      plugin._storage = wrapAsTopLevelStorage(makeFakeStorage());
      plugin._auth = makeFakeAuth({
        config: {
          uplinks: {npmjs: {url: 'https://registry.npmjs.org'}},
          getMatchedPackagesSpec: () => ({access: '$all'}),
        },
      });

      const pkg = makePackageInfo('@actions/core', {
        '3.0.1': {version: '3.0.1', dist: {integrity: REAL_PKG.integrity}},
      });
      const result = await asOnlineRequest(() =>
        plugin.filter_metadata(structuredClone(pkg)),
      );

      assert.equal(
        fetchCalls,
        0,
        "a private package's name must never be sent to an uplink it does not proxy from",
      );
      assert.ok(!('3.0.1' in result.versions));
    },
  );

  await check(
    'a version that is not valid semver (an SSRF-shaped "1\\..\\..\\x") is never fetched, and the fetched URL encodes the version',
    async () => {
      const fetchedUrls = [];
      const plugin = makeAttestations(
        {block: ['**'], fetchUpstream: true},
        {
          fetch: async url => {
            fetchedUrls.push(url);
            return {ok: true, json: async () => ({attestations: []})};
          },
        },
      );
      plugin._storage = wrapAsTopLevelStorage(makeFakeStorage());
      plugin._auth = makeFakeAuth({config: NPMJS_PROXY_CONFIG});

      const pkg = makePackageInfo('some-pkg', {
        '1\\..\\..\\x': {
          version: '1\\..\\..\\x',
          dist: {integrity: 'sha512-a'},
        },
        '1.0.0-rc+build': {
          version: '1.0.0-rc+build',
          dist: {integrity: 'sha512-b'},
        },
      });
      const result = await asOnlineRequest(() => plugin.filter_metadata(pkg));

      assert.deepEqual(fetchedUrls, [
        'https://registry.npmjs.org/-/npm/v1/attestations/some-pkg@1.0.0-rc%2Bbuild',
      ]);
      assert.deepEqual(Object.keys(result.versions), []);
    },
  );

  await check(
    'an upstream fetch error is not cached and starts the back-off; once it passes, the next read fetches again',
    async () => {
      let fetchCalls = 0;
      let failing = true;
      const plugin = makeAttestations(
        {block: ['**'], fetchUpstream: true},
        {
          fetch: async () => {
            fetchCalls += 1;
            if (failing) throw new Error('ECONNRESET');
            return {ok: true, json: async () => REAL_ATTESTATIONS};
          },
        },
      );
      plugin._storage = wrapAsTopLevelStorage(makeFakeStorage());
      plugin._auth = makeFakeAuth({config: NPMJS_PROXY_CONFIG});
      const pkg = makePackageInfo('@actions/core', {
        '3.0.1': {version: '3.0.1', dist: {integrity: REAL_PKG.integrity}},
      });

      await asOnlineRequest(async () => {
        const first = await plugin.filter_metadata(structuredClone(pkg));
        assert.ok(!('3.0.1' in first.versions));
        assert.equal(fetchCalls, 1);
        assert.equal(
          plugin._verdictCache.size,
          0,
          'a failed lookup is no verdict',
        );
        assert.ok(plugin._upstreamRetryAt.has('@actions/core@3.0.1'));

        failing = false;
        const duringBackoff = await plugin.filter_metadata(
          structuredClone(pkg),
        );
        assert.ok(!('3.0.1' in duringBackoff.versions));
        assert.equal(fetchCalls, 1, 'no new fetch inside the back-off');

        plugin._upstreamRetryAt.set('@actions/core@3.0.1', Date.now() - 1);
        const afterBackoff = await plugin.filter_metadata(structuredClone(pkg));
        assert.ok('3.0.1' in afterBackoff.versions);
        assert.equal(fetchCalls, 2);
      });
    },
  );

  await check(
    'an upstream 5xx counts as a failed lookup too: not cached, back-off started',
    async () => {
      const plugin = makeAttestations(
        {block: ['**'], fetchUpstream: true},
        {fetch: async () => ({ok: false, status: 503})},
      );
      plugin._auth = makeFakeAuth({config: NPMJS_PROXY_CONFIG});
      await asOnlineRequest(() =>
        plugin.filter_metadata(
          makePackageInfo('some-pkg', {
            '1.0.0': {version: '1.0.0', dist: {integrity: 'sha512-a'}},
          }),
        ),
      );
      assert.equal(plugin._verdictCache.size, 0);
      assert.ok(plugin._upstreamRetryAt.has('some-pkg@1.0.0'));
    },
  );

  await check(
    'an upstream 404 is a real answer: cached as an absent verdict, no back-off, no second fetch',
    async () => {
      let fetchCalls = 0;
      const plugin = makeAttestations(
        {block: ['**'], fetchUpstream: true},
        {
          fetch: async () => {
            fetchCalls += 1;
            return {ok: false, status: 404};
          },
        },
      );
      plugin._auth = makeFakeAuth({config: NPMJS_PROXY_CONFIG});
      const pkg = makePackageInfo('some-pkg', {
        '1.0.0': {version: '1.0.0', dist: {integrity: 'sha512-a'}},
      });
      await asOnlineRequest(async () => {
        await plugin.filter_metadata(structuredClone(pkg));
        const second = await plugin.filter_metadata(structuredClone(pkg));
        assert.ok(!('1.0.0' in second.versions));
      });
      assert.equal(fetchCalls, 1);
      assert.equal(plugin._upstreamRetryAt.size, 0);
      const cached = plugin._verdictCache.get('some-pkg@1.0.0');
      assert.equal(cached.verified, false);
      assert.equal(cached.integrity, 'sha512-a');
      assert.match(cached.reason, /no attestation available/);
    },
  );

  await check(
    'an offline-restricted read caches nothing, so a later online read of the same version still fetches and verifies',
    async () => {
      let fetchCalls = 0;
      const plugin = makeAttestations(
        {block: ['**'], fetchUpstream: true},
        {
          fetch: async () => {
            fetchCalls += 1;
            return {ok: true, json: async () => REAL_ATTESTATIONS};
          },
        },
      );
      plugin._storage = wrapAsTopLevelStorage(makeFakeStorage());
      plugin._auth = makeFakeAuth({config: NPMJS_PROXY_CONFIG});
      const pkg = makePackageInfo('@actions/core', {
        '3.0.1': {version: '3.0.1', dist: {integrity: REAL_PKG.integrity}},
      });

      const offline = await requestContext.run({offlineRestricted: true}, () =>
        plugin.filter_metadata(structuredClone(pkg)),
      );
      assert.ok(!('3.0.1' in offline.versions));
      assert.equal(fetchCalls, 0);
      assert.equal(plugin._verdictCache.size, 0);

      const online = await asOnlineRequest(() =>
        plugin.filter_metadata(structuredClone(pkg)),
      );
      assert.ok('3.0.1' in online.versions);
      assert.equal(fetchCalls, 1);
    },
  );

  await check(
    'a malformed upstream attestations response ([null], a non-array, a non-object) fails closed: the gated version is removed and nothing throws',
    async () => {
      const bodies = [
        {attestations: [null]},
        {attestations: 'not-an-array'},
        {attestations: [{bundle: 'not-an-object'}]},
        [null],
        null,
      ];
      for (const upstreamBody of bodies) {
        const errors = [];
        const plugin = makeAttestations(
          {block: ['**'], fetchUpstream: true},
          {
            fetch: async () => ({ok: true, json: async () => upstreamBody}),
            logger: {...NOOP_LOGGER, error: (...args) => errors.push(args)},
          },
        );
        plugin._auth = makeFakeAuth({config: NPMJS_PROXY_CONFIG});
        const result = await asOnlineRequest(() =>
          plugin.filter_metadata(
            makePackageInfo('@actions/core', {
              '3.0.1': {
                version: '3.0.1',
                dist: {integrity: REAL_PKG.integrity},
              },
            }),
          ),
        );
        const label = JSON.stringify(upstreamBody);
        assert.ok(!('3.0.1' in result.versions), label);
        assert.deepEqual(
          errors,
          [],
          `${label} must not reach the filter's catch`,
        );
      }
    },
  );

  // --- fetchUpstream: false is the default, and must mean zero network calls, ever ---

  await check(
    'fetchUpstream defaults to false -- a proxied package is blocked without ever attempting a fetch',
    async () => {
      const plugin = makeAttestations(
        {block: ['**']}, // fetchUpstream omitted -- must default to false
        {fetch: makeFakeFetch({})}, // any call at all should throw
      );
      plugin._storage = wrapAsTopLevelStorage(makeFakeStorage());

      const pkg = makePackageInfo('@actions/core', {
        '3.0.1': {version: '3.0.1', dist: {integrity: REAL_PKG.integrity}},
      });
      const first = await plugin.filter_metadata(structuredClone(pkg));
      assert.ok(!('3.0.1' in first.versions));

      await plugin.whenAllBackgroundWorkSettles();
      const second = await plugin.filter_metadata(structuredClone(pkg));
      assert.ok(
        !('3.0.1' in second.versions),
        'must remain blocked forever with fetchUpstream disabled -- never verifiable',
      );
    },
  );

  await check(
    'a persisted verdict survives a pod restart (fresh in-memory cache, same storage) without re-fetching or re-verifying',
    async () => {
      let fetchCalls = 0;
      const fakeFetch = async () => {
        fetchCalls += 1;
        return {ok: true, json: async () => REAL_ATTESTATIONS};
      };
      const sharedStorage = makeFakeStorage();
      const pkg = makePackageInfo('@actions/core', {
        '3.0.1': {version: '3.0.1', dist: {integrity: REAL_PKG.integrity}},
      });

      const podOne = makeAttestations(
        {block: ['**'], fetchUpstream: true},
        {fetch: fakeFetch},
      );
      podOne._storage = wrapAsTopLevelStorage(sharedStorage);
      podOne._auth = makeFakeAuth({config: NPMJS_PROXY_CONFIG});
      await asOnlineRequest(() => podOne.filter_metadata(structuredClone(pkg)));
      assert.equal(fetchCalls, 1);

      // A brand new plugin instance -- fresh in-memory _verdictCache, same
      // underlying storage -- simulates a pod restart.
      const podTwo = makeAttestations(
        {block: ['**'], fetchUpstream: true},
        {fetch: fakeFetch},
      );
      podTwo._storage = wrapAsTopLevelStorage(sharedStorage);
      podTwo._auth = makeFakeAuth({config: NPMJS_PROXY_CONFIG});
      const afterRestart = await asOnlineRequest(() =>
        podTwo.filter_metadata(structuredClone(pkg)),
      );
      assert.ok(
        '3.0.1' in afterRestart.versions,
        'the persisted object must be found on the FIRST call after restart, synchronously',
      );
      assert.equal(
        fetchCalls,
        1,
        'must not re-fetch -- the fast tier (persisted storage) already had the answer',
      );
    },
  );

  await check(
    'a stored .attestation object with no integrity, or a different one, is ignored',
    async () => {
      const pkg = makePackageInfo('@actions/core', {
        '3.0.1': {version: '3.0.1', dist: {integrity: REAL_PKG.integrity}},
      });
      for (const integrity of [undefined, integrityOf(Buffer.from('other'))]) {
        const storage = makeFakeStorage();
        storage.files.set(
          '@actions/core\x00@actions-core-3.0.1.attestation',
          Buffer.from(
            JSON.stringify({
              verified: true,
              integrity,
              bundle: realProvenanceBundle(),
            }),
          ),
        );
        const plugin = makeAttestations({block: ['**']});
        plugin._storage = wrapAsTopLevelStorage(storage);
        const result = await plugin.filter_metadata(structuredClone(pkg));
        assert.ok(
          !('3.0.1' in result.versions),
          `stored integrity ${integrity} must not vouch for ${REAL_PKG.integrity}`,
        );
        assert.equal(plugin._verdictCache.size, 0);
      }

      // The same object with the matching integrity is a verdict.
      const storage = makeFakeStorage();
      storage.files.set(
        '@actions/core\x00@actions-core-3.0.1.attestation',
        Buffer.from(
          JSON.stringify({
            verified: true,
            integrity: REAL_PKG.integrity,
            bundle: realProvenanceBundle(),
          }),
        ),
      );
      const plugin = makeAttestations({block: ['**']});
      plugin._storage = wrapAsTopLevelStorage(storage);
      const result = await plugin.filter_metadata(structuredClone(pkg));
      assert.ok('3.0.1' in result.versions);
    },
  );

  // --- offline-restriction matching, mirroring verdaccio-offline-enforcer's own _isRestricted() ---

  function makeAttestationsWithOfflineConfig(
    offlineEnforcerConfig,
    config = {},
  ) {
    return new Attestations(config, {
      logger: NOOP_LOGGER,
      fetch: makeFakeFetch({}),
      config: {
        middlewares: {
          '@fortmesa/verdaccio-offline-enforcer': offlineEnforcerConfig,
        },
      },
    });
  }

  await check(
    '_isOfflineRestricted: online wins even if the same identity is also listed offline elsewhere',
    () => {
      const plugin = makeAttestationsWithOfflineConfig({
        online: ['ci-online-group'],
        offline: [],
      });
      assert.equal(
        plugin._isOfflineRestricted({
          name: 'ci-bot',
          real_groups: ['ci-online-group'],
        }),
        false,
      );
    },
  );

  await check(
    '_isOfflineRestricted: an identity (by name or by group) listed offline is restricted',
    () => {
      const plugin = makeAttestationsWithOfflineConfig({
        online: [],
        offline: ['ci-offline-group'],
      });
      assert.equal(
        plugin._isOfflineRestricted({
          name: 'ci-bot',
          real_groups: ['ci-offline-group'],
        }),
        true,
      );
      assert.equal(
        plugin._isOfflineRestricted({
          name: 'ci-offline-group',
          real_groups: [],
        }),
        true,
        'matching by name directly, not just via real_groups',
      );
    },
  );

  await check(
    '_isOfflineRestricted: real_groups only -- the universal .groups superset must not be consulted',
    () => {
      const plugin = makeAttestationsWithOfflineConfig({
        online: [],
        offline: ['$authenticated'],
      });
      assert.equal(
        plugin._isOfflineRestricted({
          name: 'someone',
          real_groups: ['some-team'],
          groups: ['some-team', '$authenticated', '$all'],
        }),
        false,
        '$authenticated is a universal default in .groups, not a real_groups entry -- must not match',
      );
    },
  );

  await check(
    '_isOfflineRestricted defaults: enforceForAnonymous true, enforceForUnknown false',
    () => {
      const plugin = makeAttestationsWithOfflineConfig({
        online: [],
        offline: [],
      });
      assert.equal(
        plugin._isOfflineRestricted(undefined),
        true,
        'anonymous (no remote_user at all) is restricted by default',
      );
      assert.equal(
        plugin._isOfflineRestricted({name: 'nobody-listed', real_groups: []}),
        false,
        'an authenticated identity matching neither list is NOT restricted by default',
      );
    },
  );

  await check(
    '_isOfflineRestricted: enforceForUnknown true flips the default for unlisted authenticated identities',
    () => {
      const plugin = makeAttestationsWithOfflineConfig({
        online: [],
        offline: [],
        enforceForUnknown: true,
      });
      assert.equal(
        plugin._isOfflineRestricted({name: 'nobody-listed', real_groups: []}),
        true,
      );
    },
  );

  await check(
    '_isOfflineRestricted: no offline-enforcer config at all -- empty lists plus its own documented defaults',
    () => {
      const plugin = makeAttestations({}); // no options.config.middlewares at all
      assert.equal(plugin._isOfflineRestricted(undefined), true);
      assert.equal(
        plugin._isOfflineRestricted({name: 'anyone', real_groups: []}),
        false,
      );
    },
  );

  // --- _effectiveFetchUpstream: the static config AND this request's identity ---

  await check(
    '_effectiveFetchUpstream: false when fetchUpstream config is false, regardless of request context',
    async () => {
      const plugin = makeAttestations({fetchUpstream: false});
      await asOnlineRequest(() => {
        assert.equal(plugin._effectiveFetchUpstream(), false);
      });
    },
  );

  await check(
    '_effectiveFetchUpstream: false with no request context at all (e.g. a non-HTTP code path) -- fails closed',
    () => {
      const plugin = makeAttestations({fetchUpstream: true});
      assert.equal(plugin._effectiveFetchUpstream(), false);
    },
  );

  await check(
    '_effectiveFetchUpstream: true only when fetchUpstream is enabled AND this request is not offline-restricted',
    async () => {
      const plugin = makeAttestations({fetchUpstream: true});
      await requestContext.run({offlineRestricted: false}, () => {
        assert.equal(plugin._effectiveFetchUpstream(), true);
      });
      await requestContext.run({offlineRestricted: true}, () => {
        assert.equal(plugin._effectiveFetchUpstream(), false);
      });
    },
  );

  await check(
    'end-to-end: an offline-restricted identity gets fetchUpstream forced off for its own request, an online one does not',
    async () => {
      let fetchCalls = 0;
      let currentUser;
      const plugin = new Attestations(
        {block: ['**'], fetchUpstream: true},
        {
          logger: NOOP_LOGGER,
          // register_middlewares() starts the key relay, which fetches
          // /-/npm/v1/keys from the uplink. Only attestation fetches count.
          fetch: async url => {
            if (url.endsWith('/-/npm/v1/keys')) return {ok: false, status: 404};
            fetchCalls += 1;
            return {ok: true, status: 200, json: async () => REAL_ATTESTATIONS};
          },
          config: {
            middlewares: {
              '@fortmesa/verdaccio-offline-enforcer': {offline: ['ci-bot']},
            },
          },
        },
      );

      const app = makeApp();
      // Sets req.remote_user BEFORE register_middlewares' own ALS-populating
      // middleware runs, same as a real auth plugin would -- registration
      // order matters here, unlike the plugin's own internal middlewares.
      app.use((req, res, next) => {
        req.remote_user = currentUser;
        next();
      });
      plugin.register_middlewares(
        app,
        makeFakeAuth({config: NPMJS_PROXY_CONFIG}),
        wrapAsTopLevelStorage(makeFakeStorage()),
      );
      app.get('/:pkg', (req, res, next) => {
        const pkg = makePackageInfo('@actions/core', {
          '3.0.1': {version: '3.0.1', dist: {integrity: REAL_PKG.integrity}},
        });
        plugin
          .filter_metadata(pkg)
          .then(result => res.json(result))
          .catch(next);
      });

      const server = await listen(app);
      try {
        const port = server.address().port;

        currentUser = {name: 'ci-bot', real_groups: []};
        const restricted = await (
          await fetch(`http://localhost:${port}/x`)
        ).json();
        assert.equal(
          fetchCalls,
          0,
          "an offline-restricted identity's request must never trigger a live upstream fetch",
        );
        assert.ok(!('3.0.1' in restricted.versions));

        // Same plugin instance: the restricted read above must not have
        // left a verdict behind that answers for this one.
        currentUser = {name: 'a-developer', real_groups: []};
        const online = await (await fetch(`http://localhost:${port}/x`)).json();
        assert.equal(
          fetchCalls,
          1,
          "a non-restricted identity's request must be able to trigger the live upstream fetch",
        );
        assert.ok('3.0.1' in online.versions);
      } finally {
        server.close();
      }
    },
  );

  // --- getJson(), the plugin's own upstream GET (Node's http/https) ---

  // A local server answering each path with the given [status, headers, body].
  function upstreamApp(routes) {
    const app = makeApp();
    app.use((req, res) => {
      const route = routes[req.url];
      if (!route) return res.status(404).end();
      const [status, headers, body] = route;
      res.status(status).set(headers);
      if (body === 'hang') return; // never answers
      res.end(body);
    });
    return app;
  }

  async function startUpstream(routes) {
    const server = await listen(upstreamApp(routes));
    return {server, base: `http://127.0.0.1:${server.address().port}`};
  }

  const realGetJson = new Attestations({}, {logger: NOOP_LOGGER})._fetch;
  const plainAgent = () => new http.Agent();

  await check(
    'getJson: answers ok/status/json() for a 200 and a 404, and follows a relative redirect',
    async () => {
      const {server, base} = await startUpstream({
        '/ok': [200, {'content-type': 'application/json'}, '{"a":1}'],
        '/moved': [302, {location: '/ok'}, ''],
      });
      try {
        const ok = await realGetJson(`${base}/ok`, {agentFor: plainAgent});
        assert.equal(ok.ok, true);
        assert.equal(ok.status, 200);
        assert.deepEqual(await ok.json(), {a: 1});

        const missing = await realGetJson(`${base}/nope`, {
          agentFor: plainAgent,
        });
        assert.equal(missing.ok, false);
        assert.equal(missing.status, 404);

        const redirected = await realGetJson(`${base}/moved`, {
          agentFor: plainAgent,
        });
        assert.deepEqual(await redirected.json(), {a: 1});
      } finally {
        server.close();
      }
    },
  );

  await check(
    'getJson: a redirect loop and a timeout both reject instead of hanging',
    async () => {
      const {server, base} = await startUpstream({
        '/loop': [302, {location: '/loop'}, ''],
        '/slow': [200, {'content-type': 'application/json'}, 'hang'],
      });
      try {
        await assert.rejects(
          realGetJson(`${base}/loop`, {agentFor: plainAgent}),
          /more than 20 redirects/,
        );
        await assert.rejects(
          realGetJson(`${base}/slow`, {
            agentFor: plainAgent,
            signal: AbortSignal.timeout(200),
          }),
        );
      } finally {
        server.closeAllConnections();
        server.close();
      }
    },
  );

  await check('getJson: a redirect from https to http is refused', async () => {
    // The signing-key fixture's certificate doubles as a TLS server
    // certificate here. It has no SAN, so its CN is the hostname the
    // client checks, via servername.
    const key = fs.readFileSync(path.join(SIGNING_KEY_FIXTURE_DIR, 'tls.key'));
    const cert = fs.readFileSync(path.join(SIGNING_KEY_FIXTURE_DIR, 'tls.crt'));
    const servername = new crypto.X509Certificate(cert).subject.replace(
      /^CN=/,
      '',
    );
    const {server: plain, base: plainBase} = await startUpstream({
      '/ok': [200, {'content-type': 'application/json'}, '{"a":1}'],
    });
    const secure = https.createServer(
      {key, cert},
      upstreamApp({
        '/ok': [200, {'content-type': 'application/json'}, '{"a":1}'],
        '/downgrade': [302, {location: `${plainBase}/ok`}, ''],
      }),
    );
    await new Promise(resolve => secure.listen(0, '127.0.0.1', resolve));
    const secureBase = `https://127.0.0.1:${secure.address().port}`;
    const agentFor = url =>
      url.startsWith('https:')
        ? new https.Agent({ca: cert, servername})
        : new http.Agent();
    try {
      const ok = await realGetJson(`${secureBase}/ok`, {agentFor});
      assert.deepEqual(await ok.json(), {a: 1}, 'sanity: TLS itself works');
      await assert.rejects(
        realGetJson(`${secureBase}/downgrade`, {agentFor}),
        /refusing redirect/,
      );
    } finally {
      secure.close();
      plain.close();
    }
  });

  await check(
    'getJson: malformed JSON rejects from json(), so callers count it as a failed lookup',
    async () => {
      const {server, base} = await startUpstream({
        '/bad': [200, {'content-type': 'application/json'}, '{not json'],
      });
      try {
        const res = await realGetJson(`${base}/bad`, {agentFor: plainAgent});
        await assert.rejects(res.json(), SyntaxError);
      } finally {
        server.close();
      }
    },
  );

  // --- proxy support, mirroring verdaccio-audit's ProxyAudit exactly ---

  await check('_requestAgent uses a plain https.Agent by default', () => {
    const plugin = makeAttestations({});
    plugin._auth = {config: {}};
    const agent = plugin._requestAgent('https://registry.npmjs.org/-/x');
    assert.equal(agent.constructor, https.Agent);
  });

  await check(
    '_requestAgent uses HttpsProxyAgent when auth.config.https_proxy is set',
    () => {
      const plugin = makeAttestations({});
      plugin._auth = {config: {https_proxy: 'http://proxy.example.com:8080'}};
      const agent = plugin._requestAgent('https://registry.npmjs.org/-/x');
      assert.equal(agent.constructor.name, 'HttpsProxyAgent');
    },
  );

  await check(
    'an http:// uplink is fetched with a plain http.Agent, even with https_proxy set',
    async () => {
      const agents = [];
      const plugin = makeAttestations(
        {block: ['**'], fetchUpstream: true},
        {
          fetch: async (url, opts) => {
            agents.push(opts.agentFor(url));
            return {ok: false, status: 404};
          },
        },
      );
      plugin._auth = makeFakeAuth({
        config: {
          https_proxy: 'http://proxy.example.com:8080',
          uplinks: {mirror: {url: 'http://npm-mirror.internal:4873'}},
          getMatchedPackagesSpec: () => ({proxy: 'mirror'}),
        },
      });
      await asOnlineRequest(() =>
        plugin.filter_metadata(
          makePackageInfo('some-pkg', {
            '1.0.0': {version: '1.0.0', dist: {integrity: 'sha512-a'}},
          }),
        ),
      );
      assert.equal(agents.length, 1);
      assert.equal(
        agents[0].constructor,
        http.Agent,
        'an https.Agent on an http:// URL fails with ERR_INVALID_PROTOCOL',
      );
    },
  );

  // --- publish interception ---

  await check(
    'a publish with no .sigstore attachment is left untouched',
    async () => {
      const plugin = makeAttestations({});
      plugin._storage = wrapAsTopLevelStorage(makeFakeStorage());
      const body = {
        name: 'plain-pkg',
        versions: {'1.0.0': {version: '1.0.0', dist: {}}},
        _attachments: {'plain-pkg-1.0.0.tgz': {data: 'ZmFrZQ=='}},
      };
      await plugin._interceptPublish({body}, makeFakeRes(), 'plain-pkg');
      assert.equal(Object.keys(body._attachments).length, 1);
      assert.ok(!body.versions['1.0.0'].dist.attestations);
    },
  );

  await check(
    'a publish with a valid .sigstore attachment gets verified, stored as a single verdict object, and stripped to one attachment',
    async () => {
      const plugin = makeAttestations({});
      const storage = makeFakeStorage();
      plugin._storage = wrapAsTopLevelStorage(storage);

      const bundle = realProvenanceBundle();
      const body = {
        name: '@actions/core',
        versions: {
          '3.0.1': {version: '3.0.1', dist: {integrity: REAL_PKG.integrity}},
        },
        _attachments: {
          '@actions/core-3.0.1.tgz': {data: REAL_TARBALL_DATA},
          '@actions/core-3.0.1.sigstore': {
            data: JSON.stringify(bundle), // raw string, matching real npm/Yarn -- NOT base64
          },
        },
      };

      const res = makeFakeRes(201);
      await plugin._interceptPublish(makeFakeReq(body), res, '@actions/core');

      assert.equal(
        Object.keys(body._attachments).length,
        1,
        "Verdaccio's own hasDiffOneKey check must now pass",
      );
      assert.ok(!Object.keys(body._attachments)[0].endsWith('.sigstore'));

      const attestations = body.versions['3.0.1'].dist.attestations;
      assert.equal(attestations.verified, true);
      assert.equal(
        attestations.predicateType,
        'https://slsa.dev/provenance/v1',
      );

      assert.ok(
        !storage.files.has('@actions/core\x00@actions-core-3.0.1.attestation'),
        'must not be stored yet -- only once the response actually finishes',
      );

      res._triggerFinish();
      await plugin.whenAllBackgroundWorkSettles();

      const stored = storage.files.get(
        '@actions/core\x00@actions-core-3.0.1.attestation',
      );
      assert.ok(
        stored,
        'a single object (verdict is a field in its contents) must hold the bundle -- no separate marker file',
      );
      assert.equal(JSON.parse(stored.toString('utf8')).verified, true);
      assert.ok(
        !storage.files.has('@actions/core\x00@actions-core-3.0.1.sigstore'),
      );
    },
  );

  await check(
    'a publish with a .sigstore attachment in its real (non-base64) format still verifies correctly',
    async () => {
      // Confirmed directly against real source, not assumed: unlike the
      // tarball attachment (base64-encoded raw binary), the .sigstore
      // attachment's `data` is the JSON.stringify()'d bundle as a RAW
      // STRING -- no base64 layer at all, since a JSON string is already
      // safe to embed directly in a JSON body. Identical in npm CLI's own
      // libnpmpublish (every version that supports --provenance -- 9.9.4,
      // 10.9.8, 11.18.0 all checked, zero variation) and in Yarn's
      // @yarnpkg/plugin-npm (v3.7.0, which explicitly ports npm's own
      // implementation). A prior version of this code unconditionally
      // base64-decoded every attachment's `data`, which silently broke
      // every real --provenance publish (decoding valid JSON text as
      // base64 produces garbage bytes, logged as "unparseable .sigstore
      // attachment") -- this is the regression test for that fix.
      const plugin = makeAttestations({});
      const storage = makeFakeStorage();
      plugin._storage = wrapAsTopLevelStorage(storage);

      const bundle = realProvenanceBundle();
      const body = {
        name: '@actions/core',
        versions: {
          '3.0.1': {version: '3.0.1', dist: {integrity: REAL_PKG.integrity}},
        },
        _attachments: {
          '@actions/core-3.0.1.tgz': {data: REAL_TARBALL_DATA},
          '@actions/core-3.0.1.sigstore': {
            data: JSON.stringify(bundle), // raw string, matching real Yarn -- NOT base64
          },
        },
      };

      const res = makeFakeRes(201);
      await plugin._interceptPublish(makeFakeReq(body), res, '@actions/core');

      const attestations = body.versions['3.0.1'].dist.attestations;
      assert.equal(
        attestations.verified,
        true,
        'must correctly parse the raw (non-base64) attachment format real Yarn actually sends',
      );
      assert.equal(
        attestations.predicateType,
        'https://slsa.dev/provenance/v1',
      );
      assert.equal(
        Object.keys(body._attachments).length,
        1,
        "Verdaccio's own hasDiffOneKey check must now pass",
      );
    },
  );

  await check(
    'a brand-new package (no record in storage yet) still gets its attestation stored -- deferred past the moment the package is actually created',
    async () => {
      const plugin = makeAttestations({});
      const storage = makeFakeStorage();
      // Simulates Verdaccio's own local-storage.js: addTarball() 404s with
      // "no such package available" until the package has been created --
      // which for a brand-new package's first publish only happens in
      // Verdaccio's own core handler, downstream of this middleware.
      let packageExists = false;
      const realAddTarball = storage.addTarball.bind(storage);
      storage.addTarball = (name, filename) => {
        if (!packageExists) {
          const emitter = new EventEmitter();
          process.nextTick(() =>
            emitter.emit(
              'error',
              Object.assign(new Error('no such package available'), {
                code: 'ENOENT',
              }),
            ),
          );
          emitter.abort = () => {};
          return emitter;
        }
        return realAddTarball(name, filename);
      };
      plugin._storage = wrapAsTopLevelStorage(storage);

      const bundle = realProvenanceBundle();
      const body = {
        name: '@actions/core',
        versions: {
          '3.0.1': {version: '3.0.1', dist: {integrity: REAL_PKG.integrity}},
        },
        _attachments: {
          '@actions/core-3.0.1.tgz': {data: REAL_TARBALL_DATA},
          '@actions/core-3.0.1.sigstore': {
            data: JSON.stringify(bundle), // raw string, matching real npm/Yarn -- NOT base64
          },
        },
      };
      const res = makeFakeRes(201);
      await plugin._interceptPublish(makeFakeReq(body), res, '@actions/core');

      // Verdaccio's own core publish handler (downstream of this
      // middleware, reached via next()) is what actually creates the
      // package -- simulated here as happening sometime before 'finish'.
      packageExists = true;
      res._triggerFinish();
      await plugin.whenAllBackgroundWorkSettles();

      assert.ok(
        storage.files.has('@actions/core\x00@actions-core-3.0.1.attestation'),
        'must succeed once retried after the package actually exists',
      );
    },
  );

  await check(
    'a publish some other downstream check ends up rejecting never gets an attestation stored',
    async () => {
      const plugin = makeAttestations({});
      const storage = makeFakeStorage();
      plugin._storage = wrapAsTopLevelStorage(storage);

      const bundle = realProvenanceBundle();
      const body = {
        name: '@actions/core',
        versions: {
          '3.0.1': {version: '3.0.1', dist: {integrity: REAL_PKG.integrity}},
        },
        _attachments: {
          '@actions/core-3.0.1.tgz': {data: REAL_TARBALL_DATA},
          '@actions/core-3.0.1.sigstore': {
            data: JSON.stringify(bundle), // raw string, matching real npm/Yarn -- NOT base64
          },
        },
      };
      // e.g. security-filter's own publish gate rejected it downstream.
      const res = makeFakeRes(403);
      await plugin._interceptPublish(makeFakeReq(body), res, '@actions/core');
      res._triggerFinish();
      await plugin.whenAllBackgroundWorkSettles();

      assert.ok(
        !storage.files.has('@actions/core\x00@actions-core-3.0.1.attestation'),
        'a rejected publish must never leave an orphaned verdict object in storage',
      );
    },
  );

  await check(
    'a publish with a tampered .sigstore attachment is still stripped (so Verdaccio accepts the publish), but marked unverified',
    async () => {
      const plugin = makeAttestations({});
      const storage = makeFakeStorage();
      plugin._storage = wrapAsTopLevelStorage(storage);

      // A different tarball, honestly described by its own integrity, with
      // the real bundle (which attests to the real tarball) attached.
      const otherTarball = Buffer.from('not the attested tarball');
      const tamperedBundle = realProvenanceBundle();
      const body = {
        name: '@actions/core',
        versions: {
          '3.0.1': {
            version: '3.0.1',
            dist: {integrity: integrityOf(otherTarball)},
          },
        },
        _attachments: {
          '@actions/core-3.0.1.tgz': {data: otherTarball.toString('base64')},
          '@actions/core-3.0.1.sigstore': {
            data: JSON.stringify(tamperedBundle), // raw string, matching real npm/Yarn -- NOT base64,
          },
        },
      };

      const res = makeFakeRes(201);
      await plugin._interceptPublish(makeFakeReq(body), res, '@actions/core');
      res._triggerFinish();
      await plugin.whenAllBackgroundWorkSettles();

      assert.equal(Object.keys(body._attachments).length, 1);
      assert.equal(body.versions['3.0.1'].dist.attestations.verified, false);
      assert.match(
        body.versions['3.0.1'].dist.attestations.reason,
        /digest does not match/,
      );
      const stored = storage.files.get(
        '@actions/core\x00@actions-core-3.0.1.attestation',
      );
      assert.ok(
        stored,
        'a failed verdict is still stored -- the bundle was present and evaluated, just did not verify',
      );
      const parsed = JSON.parse(stored.toString('utf8'));
      assert.equal(parsed.verified, false);
      assert.match(parsed.reason, /digest does not match/);
    },
  );

  await check(
    'a rejected (non-2xx) publish caches nothing, so a gated read of that version is still blocked',
    async () => {
      const plugin = makeAttestations({block: ['**']});
      plugin._storage = wrapAsTopLevelStorage(makeFakeStorage());
      const body = makeRealPublishBody();
      const res = makeFakeRes(403);
      await plugin._interceptPublish(makeFakeReq(body), res, '@actions/core');
      assert.equal(
        body.versions['3.0.1'].dist.attestations.verified,
        true,
        'the bundle itself verified',
      );
      assert.equal(
        plugin._verdictCache.size,
        0,
        'nothing cached before finish',
      );
      res._triggerFinish();
      await plugin.whenAllBackgroundWorkSettles();

      assert.equal(plugin._verdictCache.size, 0);
      const result = await plugin.filter_metadata(makeRealPackageInfo());
      assert.ok(!('3.0.1' in result.versions));
    },
  );

  await check(
    'a transient sigstore failure at publish is stored with transient:true, and a later read verifies the stored bundle again',
    async () => {
      const tufCache = fs.mkdtempSync(
        path.join(os.tmpdir(), 'verdaccio-attestations-tuf-'),
      );
      try {
        // No trust root is seeded for this mirror, so sigstore.verify()
        // throws a TUFError before any network call: it could not finish.
        const plugin = makeAttestations({
          block: ['**'],
          sigstore: {
            tufMirrorURL: 'http://127.0.0.1:1',
            tufCachePath: tufCache,
          },
        });
        const storage = makeFakeStorage();
        plugin._storage = wrapAsTopLevelStorage(storage);
        const body = makeRealPublishBody();
        const res = makeFakeRes(201);
        await plugin._interceptPublish(makeFakeReq(body), res, '@actions/core');
        res._triggerFinish();
        await plugin.whenAllBackgroundWorkSettles();

        assert.equal(body.versions['3.0.1'].dist.attestations.verified, false);
        assert.equal(
          plugin._verdictCache.size,
          0,
          'a transient result is no verdict',
        );
        const stored = JSON.parse(
          storage.files
            .get('@actions/core\x00@actions-core-3.0.1.attestation')
            .toString('utf8'),
        );
        assert.equal(stored.transient, true);
        assert.equal(stored.verified, false);
        assert.equal(stored.integrity, REAL_PKG.integrity);
        assert.deepEqual(stored.bundle, realProvenanceBundle());

        // The trust root is reachable again. fetchUpstream is off: the
        // stored bundle is local and needs no uplink.
        plugin.sigstoreOptions = {};
        const result = await plugin.filter_metadata(makeRealPackageInfo());
        assert.ok('3.0.1' in result.versions);
        assert.equal(
          plugin._verdictCache.get('@actions/core@3.0.1').verified,
          true,
        );
      } finally {
        fs.rmSync(tufCache, {recursive: true, force: true});
      }
    },
  );

  await check(
    'a PUT from someone allow_publish denies, or with no remote_user, is never intercepted: no verification, no cached verdict',
    async () => {
      for (const {auth, remoteUser} of [
        {
          auth: makeFakeAuth({publish: false}),
          remoteUser: {name: undefined, real_groups: [], groups: ['$all']},
        },
        {auth: makeFakeAuth({publish: false}), remoteUser: DEV_USER},
        {auth: makeFakeAuth(), remoteUser: undefined},
      ]) {
        const plugin = makeAttestations({block: ['**']});
        const storage = makeFakeStorage();
        const app = makeApp();
        app.use((req, res, next) => {
          req.remote_user = remoteUser;
          next();
        });
        plugin.register_middlewares(app, auth, wrapAsTopLevelStorage(storage));
        // Verdaccio's router would answer 403 here; accepting instead shows
        // that the plugin, not a rejected response, kept the cache empty.
        app.put('/:package', (req, res) => {
          res.status(201).json({
            attachmentCount: Object.keys(req.body._attachments).length,
            attestations: req.body.versions['3.0.1'].dist.attestations ?? null,
          });
        });

        const server = await listen(app);
        try {
          const response = await fetch(
            `http://localhost:${server.address().port}/%40actions%2Fcore`,
            {
              method: 'PUT',
              headers: {'content-type': 'application/json'},
              body: JSON.stringify(makeRealPublishBody()),
            },
          );
          const json = await response.json();
          await plugin.whenAllBackgroundWorkSettles();
          const label = JSON.stringify(remoteUser);
          assert.equal(json.attachmentCount, 2, `${label}: body left as sent`);
          assert.equal(json.attestations, null, `${label}: never verified`);
          assert.equal(plugin._verdictCache.size, 0, label);
          assert.equal(storage.files.size, 0, label);
        } finally {
          server.close();
        }
      }
    },
  );

  await check(
    'PUT or DELETE of a .attestation file, and a publish carrying a .attestation attachment, get 403',
    async () => {
      const plugin = makeAttestations({});
      const storage = makeFakeStorage();
      const app = makeApp();
      app.use((req, res, next) => {
        req.remote_user = DEV_USER;
        next();
      });
      plugin.register_middlewares(
        app,
        makeFakeAuth(),
        wrapAsTopLevelStorage(storage),
      );
      let reachedVerdaccio = 0;
      app.use((req, res) => {
        reachedVerdaccio += 1;
        res.status(201).json({ok: true});
      });

      const server = await listen(app);
      try {
        const base = `http://localhost:${server.address().port}`;
        const attestationPath = `${base}/${encodeURIComponent('@actions/core')}/-/@actions-core-3.0.1.attestation`;

        const put = await fetch(`${attestationPath}/-rev/1`, {
          method: 'PUT',
          headers: {'content-type': 'application/octet-stream'},
          body: '{"verified":true}',
        });
        assert.equal(put.status, 403);

        const del = await fetch(`${attestationPath}/-rev/1`, {
          method: 'DELETE',
        });
        assert.equal(del.status, 403);

        const body = makeRealPublishBody();
        body._attachments['@actions-core-3.0.1.attestation'] = {
          data: Buffer.from('{"verified":true}').toString('base64'),
        };
        const publish = await fetch(
          `${base}/${encodeURIComponent('@actions/core')}`,
          {
            method: 'PUT',
            headers: {'content-type': 'application/json'},
            body: JSON.stringify(body),
          },
        );
        assert.equal(publish.status, 403);

        assert.equal(reachedVerdaccio, 0);
        assert.equal(storage.files.size, 0);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'malformed publish bodies (a non-object version entry, a "null" bundle, a non-object .sigstore, a DSSE payload of null) call next() and raise no unhandled rejection',
    async () => {
      const rejections = [];
      const onRejection = err => rejections.push(err);
      process.on('unhandledRejection', onRejection);

      const plugin = makeAttestations({});
      const app = makeApp();
      app.use((req, res, next) => {
        req.remote_user = DEV_USER;
        next();
      });
      plugin.register_middlewares(
        app,
        makeFakeAuth(),
        wrapAsTopLevelStorage(makeFakeStorage()),
      );
      app.put('/:package', (req, res) => {
        const meta = req.body.versions['3.0.1'];
        res.status(201).json({verified: meta?.dist?.attestations?.verified});
      });

      const nonObjectVersion = makeRealPublishBody();
      nonObjectVersion.versions['3.0.1'] = 'not-an-object';
      const nullBundle = makeRealPublishBody();
      nullBundle._attachments['@actions/core-3.0.1.sigstore'].data = 'null';
      const nonObjectSigstore = makeRealPublishBody();
      nonObjectSigstore._attachments['@actions/core-3.0.1.sigstore'] = null;
      const nullPayload = makeRealPublishBody();
      const bundle = realProvenanceBundle();
      bundle.dsseEnvelope.payload = Buffer.from('null').toString('base64');
      nullPayload._attachments['@actions/core-3.0.1.sigstore'].data =
        JSON.stringify(bundle);

      const server = await listen(app);
      try {
        for (const [label, body, verified] of [
          ['non-object version entry', nonObjectVersion, undefined],
          ['"null" bundle', nullBundle, undefined],
          ['non-object .sigstore', nonObjectSigstore, undefined],
          ['DSSE payload of null', nullPayload, false],
        ]) {
          const response = await fetch(
            `http://localhost:${server.address().port}/%40actions%2Fcore`,
            {
              method: 'PUT',
              headers: {'content-type': 'application/json'},
              body: JSON.stringify(body),
            },
          );
          assert.equal(response.status, 201, `${label}: next() was called`);
          assert.equal((await response.json()).verified, verified, label);
        }
        await plugin.whenAllBackgroundWorkSettles();
        await new Promise(r => setImmediate(r));
        assert.deepEqual(rejections, []);
      } finally {
        server.close();
        process.off('unhandledRejection', onRejection);
      }
    },
  );

  await check(
    'a publish whose tarball does not match dist.integrity is unverified and unsigned, even with a valid bundle',
    async () => {
      __resetSharedStateForTests();
      const plugin = makeAttestations({
        sigstore: {
          trustedPublishers: [
            {subjectAlternativeName: 'https://github.com/actions/toolkit/**'},
          ],
          signingKeys: [SIGNING_KEY_FIXTURE_DIR],
        },
      });
      plugin._storage = wrapAsTopLevelStorage(makeFakeStorage());
      const body = makeRealPublishBody();
      body._attachments['core-3.0.1.tgz'].data = Buffer.from(
        'not the real tarball',
      ).toString('base64');
      const res = makeFakeRes(201);
      await plugin._interceptPublish(makeFakeReq(body), res, '@actions/core');
      res._triggerFinish();
      await plugin.whenAllBackgroundWorkSettles();

      const dist = body.versions['3.0.1'].dist;
      assert.equal(dist.attestations.verified, false);
      assert.equal(
        dist.attestations.reason,
        'uploaded tarball does not match dist.integrity',
      );
      assert.equal(dist.signatures, undefined);
    },
  );

  await check(
    'a publish whose dist.integrity lists the attested digest plus a second sha512 for the uploaded tarball is unverified and unsigned',
    async () => {
      __resetSharedStateForTests();
      const plugin = makeAttestations({
        sigstore: {
          trustedPublishers: [
            {subjectAlternativeName: 'https://github.com/actions/toolkit/**'},
          ],
          signingKeys: [SIGNING_KEY_FIXTURE_DIR],
        },
      });
      plugin._storage = wrapAsTopLevelStorage(makeFakeStorage());
      const swapped = Buffer.from('a different tarball');
      const body = makeRealPublishBody();
      body._attachments['core-3.0.1.tgz'].data = swapped.toString('base64');
      body.versions['3.0.1'].dist.integrity =
        `${REAL_PKG.integrity} ${integrityOf(swapped)}`;
      const res = makeFakeRes(201);
      await plugin._interceptPublish(makeFakeReq(body), res, '@actions/core');
      res._triggerFinish();
      await plugin.whenAllBackgroundWorkSettles();

      const dist = body.versions['3.0.1'].dist;
      assert.equal(dist.attestations.verified, false);
      assert.equal(
        dist.attestations.reason,
        'dist.integrity is not a single sha512 digest',
      );
      assert.equal(dist.signatures, undefined);
    },
  );

  // An Express app with this plugin's middlewares, a user set the way an
  // auth plugin would, and a stand-in for Verdaccio's publish route that
  // reports what it received.
  async function startPublishApp(plugin, remoteUser = DEV_USER) {
    const app = makeApp();
    app.use((req, res, next) => {
      req.remote_user = remoteUser;
      next();
    });
    plugin.register_middlewares(
      app,
      makeFakeAuth(),
      wrapAsTopLevelStorage(makeFakeStorage()),
    );
    app.put('/:package', (req, res) => {
      res.status(201).json({context: requestContext.getStore() ?? null});
    });
    return listen(app);
  }

  await check(
    'a publish body over max_body_size gets 413, and malformed JSON gets 400, before Verdaccio sees it',
    async () => {
      const plugin = makeAttestations({}, {config: {max_body_size: '1kb'}});
      const server = await startPublishApp(plugin);
      try {
        const url = `http://localhost:${server.address().port}/some-pkg`;
        const tooBig = await fetch(url, {
          method: 'PUT',
          headers: {'content-type': 'application/json'},
          body: JSON.stringify({padding: 'x'.repeat(4096)}),
        });
        assert.equal(tooBig.status, 413);

        const malformed = await fetch(url, {
          method: 'PUT',
          headers: {'content-type': 'application/json'},
          body: '{"versions": ',
        });
        assert.equal(malformed.status, 400);
      } finally {
        server.close();
      }
    },
  );

  await check(
    "the request's offline-restriction context survives body parsing, so a handler after this plugin still sees it",
    async () => {
      const plugin = makeAttestations(
        {},
        {
          config: {
            middlewares: {
              '@fortmesa/verdaccio-offline-enforcer': {offline: ['ci-bot']},
            },
          },
        },
      );
      const server = await startPublishApp(plugin, {
        name: 'ci-bot',
        real_groups: [],
      });
      try {
        // The rest of the body arrives after the parser is already waiting,
        // so its 'end' event comes from the socket rather than from a tick
        // scheduled inside the request's context.
        const body = JSON.stringify({name: 'some-pkg', versions: {}});
        const response = await new Promise((resolve, reject) => {
          const req = http.request(
            {
              port: server.address().port,
              path: '/some-pkg',
              method: 'PUT',
              headers: {
                'content-type': 'application/json',
                'content-length': Buffer.byteLength(body),
              },
            },
            res => {
              let data = '';
              res.on('data', d => (data += d));
              res.on('end', () => resolve({status: res.statusCode, data}));
            },
          );
          req.on('error', reject);
          req.write(body.slice(0, 5));
          setTimeout(() => req.end(body.slice(5)), 50);
        });
        assert.equal(response.status, 201);
        assert.deepEqual(JSON.parse(response.data).context, {
          offlineRestricted: true,
        });
      } finally {
        server.close();
      }
    },
  );

  // --- GET /-/npm/v1/attestations/:pkgAtVersion ---

  // A request from DEV_USER, the way Express hands the route handler one.
  function makeGetReq(pkgAtVersion, remoteUser = DEV_USER) {
    return {params: {pkgAtVersion}, remote_user: remoteUser};
  }

  await check(
    'serves an already-locally-stored verified bundle without any upstream fetch',
    async () => {
      const plugin = makeAttestations({}, {fetch: makeFakeFetch({})});
      const storage = makeFakeStorage();
      plugin._storage = wrapAsTopLevelStorage(storage);
      plugin._auth = makeFakeAuth();
      await plugin._storeVerdictAndBundle(
        '@actions/core',
        '3.0.1',
        REAL_PKG.integrity,
        realProvenanceBundle(),
        {verified: true},
      );

      const res = makeRecordingRes();
      await plugin._handleGetAttestations(
        makeGetReq('@actions/core@3.0.1'),
        res,
      );
      assert.equal(res.statusCode, 200);
      assert.ok(res.body.attestations[0].bundle);
    },
  );

  await check(
    'the attestations route applies allow_access: a denied user gets the denial status and no bundle, a request with no remote_user gets 403',
    async () => {
      const plugin = makeAttestations({}, {fetch: makeFakeFetch({})});
      plugin._storage = wrapAsTopLevelStorage(makeFakeStorage());
      await plugin._storeVerdictAndBundle(
        '@actions/core',
        '3.0.1',
        REAL_PKG.integrity,
        realProvenanceBundle(),
        {verified: true},
      );

      plugin._auth = makeFakeAuth({access: false, denyStatus: 401});
      const denied = makeRecordingRes();
      await plugin._handleGetAttestations(
        makeGetReq('@actions/core@3.0.1'),
        denied,
      );
      assert.equal(denied.statusCode, 401);
      assert.equal(denied.body, undefined);

      plugin._auth = makeFakeAuth();
      const noUser = makeRecordingRes();
      await plugin._handleGetAttestations(
        makeGetReq('@actions/core@3.0.1', null),
        noUser,
      );
      assert.equal(noUser.statusCode, 403);
      assert.equal(noUser.body, undefined);
    },
  );

  await check(
    'with fetchUpstream disabled (default), a genuine miss 404s without attempting a fetch',
    async () => {
      const plugin = makeAttestations({}, {fetch: makeFakeFetch({})}); // any call should throw
      plugin._storage = wrapAsTopLevelStorage(makeFakeStorage());
      plugin._auth = makeFakeAuth({config: NPMJS_PROXY_CONFIG});

      const res = makeRecordingRes();
      await plugin._handleGetAttestations(
        makeGetReq('@actions/core@3.0.1'),
        res,
      );
      assert.equal(res.statusCode, 404);
    },
  );

  await check(
    'with fetchUpstream enabled, a genuine miss relays the raw upstream response without caching it',
    async () => {
      let fetchCalls = 0;
      const plugin = makeAttestations(
        {fetchUpstream: true},
        {
          fetch: async () => {
            fetchCalls += 1;
            return {ok: true, status: 200, json: async () => REAL_ATTESTATIONS};
          },
        },
      );
      const storage = makeFakeStorage();
      plugin._storage = wrapAsTopLevelStorage(storage);
      plugin._auth = makeFakeAuth({config: NPMJS_PROXY_CONFIG});

      const res = makeRecordingRes();
      await asOnlineRequest(() =>
        plugin._handleGetAttestations(makeGetReq('@actions/core@3.0.1'), res),
      );
      assert.equal(res.statusCode, 200);
      assert.equal(fetchCalls, 1);
      assert.deepEqual(res.body, REAL_ATTESTATIONS);
      assert.equal(
        storage.files.size,
        0,
        'a bare GET has no dist.integrity to verify against, so nothing gets cached',
      );
    },
  );

  await check(
    'with fetchUpstream enabled, a package with no proxy configured is never looked up upstream',
    async () => {
      const plugin = makeAttestations(
        {fetchUpstream: true},
        {fetch: makeFakeFetch({})}, // any call should throw
      );
      plugin._storage = wrapAsTopLevelStorage(makeFakeStorage());
      plugin._auth = makeFakeAuth({
        config: {
          uplinks: NPMJS_PROXY_CONFIG.uplinks,
          getMatchedPackagesSpec: () => ({}),
        },
      });

      const res = makeRecordingRes();
      await asOnlineRequest(() =>
        plugin._handleGetAttestations(
          makeGetReq('@private-scope/internal@1.0.0'),
          res,
        ),
      );
      assert.equal(res.statusCode, 404);
    },
  );

  await check(
    'with fetchUpstream enabled, an offline-restricted identity still gets a 404, never a live fetch, on the dedicated attestations route',
    async () => {
      // The exact path docs/configuration.md's "Per-request override"
      // section calls out as the tricky one: verdaccio-offline-enforcer's
      // own middleware exempts anything under /-/ (this route included),
      // so a runtime signal from that plugin would never restrict this
      // request -- this plugin has to enforce the restriction itself,
      // independent of whether offline-enforcer's own middleware even ran.
      let fetchCalls = 0;
      const plugin = makeAttestations(
        {fetchUpstream: true},
        {
          fetch: async () => {
            fetchCalls += 1;
            return {ok: true, status: 200, json: async () => REAL_ATTESTATIONS};
          },
        },
      );
      plugin._storage = wrapAsTopLevelStorage(makeFakeStorage());
      plugin._auth = makeFakeAuth({config: NPMJS_PROXY_CONFIG});

      const res = makeRecordingRes();
      await requestContext.run({offlineRestricted: true}, () =>
        plugin._handleGetAttestations(makeGetReq('@actions/core@3.0.1'), res),
      );
      assert.equal(
        fetchCalls,
        0,
        "an offline-restricted identity's request to this route must never trigger a live upstream fetch",
      );
      assert.equal(res.statusCode, 404);
    },
  );

  await check(
    '404s when neither local storage nor (disabled) upstream has anything',
    async () => {
      const plugin = makeAttestations({}, {fetch: makeFakeFetch({})});
      plugin._storage = wrapAsTopLevelStorage(makeFakeStorage());
      plugin._auth = makeFakeAuth({config: NPMJS_PROXY_CONFIG});

      const res = makeRecordingRes();
      await plugin._handleGetAttestations(
        makeGetReq('nonexistent-pkg@1.0.0'),
        res,
      );
      assert.equal(res.statusCode, 404);
    },
  );

  await check(
    'a name/version shaped like a storage-key escape attempt is rejected with 400, not passed to the storage backend',
    async () => {
      const plugin = makeAttestations({}, {fetch: makeFakeFetch({})}); // any storage/fetch call should throw
      plugin._storage = wrapAsTopLevelStorage(makeFakeStorage());

      async function statusFor(pkgAtVersion) {
        let statusCode;
        const res = {
          status(code) {
            statusCode = code;
            return this;
          },
          json() {
            return this;
          },
          end() {},
        };
        await plugin._handleGetAttestations({params: {pkgAtVersion}}, res);
        return statusCode;
      }

      // Express's own router only ever decodes req.params once (verified
      // against the installed express/router package) -- this exercises
      // exactly the value this method actually receives, not a raw URL.
      assert.equal(
        await statusFor('../../../etc/passwd@1.0.0'),
        400,
        'a ".." path segment in the name must not reach the storage layer',
      );
      assert.equal(
        await statusFor('left-pad@../../etc/passwd'),
        400,
        'a ".." path segment in the version must not reach the storage layer',
      );
      assert.equal(
        await statusFor('left-pad@1.0.0/../../etc/passwd'),
        400,
        'a "/" in the version (not just "..") must also be rejected',
      );
      assert.equal(
        await statusFor('@scope/nested/pkg@1.0.0'),
        400,
        'more than one "/" in the name must be rejected',
      );
    },
  );

  // --- true end-to-end: a real Express app, real HTTP requests, real routing ---

  await check(
    'end-to-end: a real PUT publish request with a .sigstore attachment is intercepted through actual Express routing',
    async () => {
      const plugin = makeAttestations({});
      const storage = makeFakeStorage();
      const app = makeApp();
      // A real auth plugin sets req.remote_user before plugin middlewares run.
      app.use((req, res, next) => {
        req.remote_user = DEV_USER;
        next();
      });
      plugin.register_middlewares(
        app,
        makeFakeAuth(),
        wrapAsTopLevelStorage(storage),
      );
      // Simulates Verdaccio's own core publish route, mounted after this
      // plugin's middleware -- proves the modified body actually reaches
      // downstream handlers correctly, not just that our own method works
      // in isolation.
      app.use(express.json());
      app.put('/:package', (req, res) => {
        res.status(201).json({
          attachmentCount: Object.keys(req.body._attachments).length,
          attestations: req.body.versions['3.0.1'].dist.attestations,
        });
      });

      const server = await new Promise(resolve => {
        const s = app.listen(0, () => resolve(s));
      });
      try {
        const port = server.address().port;
        const bundle = realProvenanceBundle();
        const publishBody = JSON.stringify({
          name: '@actions/core',
          versions: {
            '3.0.1': {version: '3.0.1', dist: {integrity: REAL_PKG.integrity}},
          },
          _attachments: {
            '@actions/core-3.0.1.tgz': {data: REAL_TARBALL_DATA},
            '@actions/core-3.0.1.sigstore': {
              data: JSON.stringify(bundle), // raw string, matching real npm/Yarn -- NOT base64
            },
          },
        });

        const response = await fetch(
          `http://localhost:${port}/%40actions%2Fcore`,
          {
            method: 'PUT',
            headers: {'content-type': 'application/json'},
            body: publishBody,
          },
        );
        const json = await response.json();
        assert.equal(response.status, 201);
        assert.equal(
          json.attachmentCount,
          1,
          'the real Express request body must have been mutated down to one attachment',
        );
        assert.equal(
          json.attestations.verified,
          true,
          json.attestations.reason,
        );
      } finally {
        server.close();
      }
    },
  );

  await check(
    'end-to-end: a real GET to the attestations route correctly decodes a scoped package name through actual Express routing',
    async () => {
      const plugin = makeAttestations({});
      const storage = makeFakeStorage();
      plugin._storage = wrapAsTopLevelStorage(storage);
      await plugin._storeVerdictAndBundle(
        '@actions/core',
        '3.0.1',
        REAL_PKG.integrity,
        realProvenanceBundle(),
        {verified: true},
      );

      const app = makeApp();
      // A real auth plugin sets req.remote_user before plugin middlewares run.
      app.use((req, res, next) => {
        req.remote_user = DEV_USER;
        next();
      });
      plugin.register_middlewares(
        app,
        makeFakeAuth(),
        wrapAsTopLevelStorage(storage),
      );

      const server = await new Promise(resolve => {
        const s = app.listen(0, () => resolve(s));
      });
      try {
        const port = server.address().port;
        const response = await fetch(
          `http://localhost:${port}/-/npm/v1/attestations/${encodeURIComponent('@actions/core')}@3.0.1`,
        );
        assert.equal(response.status, 200);
        const json = await response.json();
        assert.ok(json.attestations[0].bundle);
      } finally {
        server.close();
      }
    },
  );

  // --- DELETE /:pkg/-/:filename/-rev/:revision -- verdict follows its tarball's lifecycle ---

  await check(
    'end-to-end: deleting a real tarball also removes its stored verdict',
    async () => {
      const plugin = makeAttestations({});
      const storage = makeFakeStorage();
      plugin._storage = wrapAsTopLevelStorage(storage);
      await plugin._storeVerdictAndBundle(
        '@actions/core',
        '3.0.1',
        REAL_PKG.integrity,
        realProvenanceBundle(),
        {verified: true},
      );
      assert.ok(
        storage.files.has('@actions/core\x00@actions-core-3.0.1.attestation'),
        'sanity check: the verdict is actually there before the delete',
      );

      const app = makeApp();
      // A real auth plugin sets req.remote_user before plugin middlewares run.
      app.use((req, res, next) => {
        req.remote_user = DEV_USER;
        next();
      });
      plugin.register_middlewares(
        app,
        makeFakeAuth(),
        wrapAsTopLevelStorage(storage),
      );
      app.delete('/:package/-/:filename/-rev/:revision', (req, res) => {
        res.status(200).json({ok: true});
      });

      const server = await new Promise(resolve => {
        const s = app.listen(0, () => resolve(s));
      });
      try {
        const port = server.address().port;
        const response = await fetch(
          `http://localhost:${port}/${encodeURIComponent('@actions/core')}/-/core-3.0.1.tgz/-rev/1`,
          {method: 'DELETE'},
        );
        assert.equal(response.status, 200);
        // The cleanup itself is deferred to res.on('finish'), same as
        // publish -- give it a tick to actually run.
        await new Promise(r => setTimeout(r, 50));
        assert.ok(
          !storage.files.has(
            '@actions/core\x00@actions-core-3.0.1.attestation',
          ),
          'the verdict must be removed along with its tarball',
        );
      } finally {
        server.close();
      }
    },
  );

  await check(
    'end-to-end: deleting a tarball with no stored verdict at all is a harmless no-op',
    async () => {
      const plugin = makeAttestations({});
      const storage = makeFakeStorage();

      const app = makeApp();
      // A real auth plugin sets req.remote_user before plugin middlewares run.
      app.use((req, res, next) => {
        req.remote_user = DEV_USER;
        next();
      });
      plugin.register_middlewares(
        app,
        makeFakeAuth(),
        wrapAsTopLevelStorage(storage),
      );
      app.delete('/:package/-/:filename/-rev/:revision', (req, res) => {
        res.status(200).json({ok: true});
      });

      const server = await new Promise(resolve => {
        const s = app.listen(0, () => resolve(s));
      });
      try {
        const port = server.address().port;
        const response = await fetch(
          `http://localhost:${port}/never-verified-pkg/-/never-verified-pkg-1.0.0.tgz/-rev/1`,
          {method: 'DELETE'},
        );
        assert.equal(
          response.status,
          200,
          'the delete itself must still succeed',
        );
      } finally {
        server.close();
      }
    },
  );

  await check(
    'end-to-end: a rejected tarball delete (non-2xx) never triggers verdict cleanup',
    async () => {
      const plugin = makeAttestations({});
      const storage = makeFakeStorage();
      plugin._storage = wrapAsTopLevelStorage(storage);
      await plugin._storeVerdictAndBundle(
        '@actions/core',
        '3.0.1',
        REAL_PKG.integrity,
        realProvenanceBundle(),
        {verified: true},
      );

      const app = makeApp();
      // A real auth plugin sets req.remote_user before plugin middlewares run.
      app.use((req, res, next) => {
        req.remote_user = DEV_USER;
        next();
      });
      plugin.register_middlewares(
        app,
        makeFakeAuth(),
        wrapAsTopLevelStorage(storage),
      );
      app.delete('/:package/-/:filename/-rev/:revision', (req, res) => {
        res.status(403).json({error: 'forbidden'});
      });

      const server = await new Promise(resolve => {
        const s = app.listen(0, () => resolve(s));
      });
      try {
        const port = server.address().port;
        await fetch(
          `http://localhost:${port}/${encodeURIComponent('@actions/core')}/-/core-3.0.1.tgz/-rev/1`,
          {method: 'DELETE'},
        );
        await new Promise(r => setTimeout(r, 50));
        assert.ok(
          storage.files.has('@actions/core\x00@actions-core-3.0.1.attestation'),
          'a rejected delete must leave the verdict (and the real tarball it belongs to) untouched',
        );
      } finally {
        server.close();
      }
    },
  );

  // --- in-memory-only fallback: no storage.localStorage reachable at all ---

  await check(
    'with no persistent storage at all, verification still works via the in-memory cache alone (no crash, no persist attempt)',
    async () => {
      // sharedStorage is module-level (see index.js) and persists across
      // every test in this process -- earlier tests in this same file have
      // already called register_middlewares(), so without resetting it
      // here, _getLocalStorage() would find THEIR leftover storage instead
      // of genuinely exercising "nothing reachable at all".
      __resetSharedStateForTests();

      let fetchCalls = 0;
      const plugin = makeAttestations(
        {block: ['**'], fetchUpstream: true},
        {
          fetch: async () => {
            fetchCalls += 1;
            return {ok: true, status: 200, json: async () => REAL_ATTESTATIONS};
          },
        },
      );
      // An auth handle only, so the package has an uplink to fetch from.
      plugin._auth = makeFakeAuth({config: NPMJS_PROXY_CONFIG});
      // Deliberately never sets plugin._storage at all -- _getLocalStorage()
      // must return null, and every storage-touching path must degrade to
      // in-memory-only rather than throw. Must stay @actions/core@3.0.1 --
      // the real attestation's subject is bound to that exact name/version,
      // so verification would genuinely (correctly) fail against any other
      // package name, defeating the point of this test.
      const pkg = makePackageInfo('@actions/core', {
        '3.0.1': {version: '3.0.1', dist: {integrity: REAL_PKG.integrity}},
      });

      await asOnlineRequest(async () => {
        const first = await plugin.filter_metadata(structuredClone(pkg));
        assert.ok(
          '3.0.1' in first.versions,
          'must resolve correctly on the very first read even with no persistent storage reachable',
        );

        const second = await plugin.filter_metadata(structuredClone(pkg));
        assert.ok(
          '3.0.1' in second.versions,
          'the in-memory _verdictCache alone must be enough to answer the second check',
        );
        assert.equal(fetchCalls, 1, 'must not have crashed or re-fetched');
      });
    },
  );

  // --- keys.js: loading our own signing key(s) ---

  await check(
    'keys.js: loadSigningKeys loads a real EC P-256 tls.crt/tls.key pair and computes a stable keyid',
    async () => {
      const [key] = loadSigningKeys([SIGNING_KEY_FIXTURE_DIR]);
      assert.match(key.keyid, /^SHA256:[A-Za-z0-9+/]{40,50}$/);
      assert.equal(key.publicKeyEntry.keyid, key.keyid);
      assert.equal(key.publicKeyEntry.keytype, 'ecdsa-sha2-nistp256');
      assert.equal(key.publicKeyEntry.scheme, 'ecdsa-sha2-nistp256');
      assert.ok(
        key.expires,
        "expires must be populated from the cert's own validTo",
      );

      // Loading the same directory twice must produce the exact same keyid --
      // a stable, reproducible function of the public key alone, not
      // per-process randomness.
      const [again] = loadSigningKeys([SIGNING_KEY_FIXTURE_DIR]);
      assert.equal(again.keyid, key.keyid);
    },
  );

  await check(
    'keys.js: a signature from sign() verifies with the exact PEM-reconstruction technique real npm/pacote clients use',
    async () => {
      const [key] = loadSigningKeys([SIGNING_KEY_FIXTURE_DIR]);
      const message = 'left-pad@1.0.0:sha512-abc123';
      const sig = key.sign(message);

      const pem = `-----BEGIN PUBLIC KEY-----\n${key.publicKeyEntry.key.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----\n`;
      const verifier = crypto.createVerify('SHA256');
      verifier.write(message);
      verifier.end();
      assert.equal(verifier.verify(pem, sig, 'base64'), true);

      const tamperedVerifier = crypto.createVerify('SHA256');
      tamperedVerifier.write('left-pad@1.0.0:sha512-tampered');
      tamperedVerifier.end();
      assert.equal(
        tamperedVerifier.verify(pem, sig, 'base64'),
        false,
        'a tampered message must not verify against the same signature',
      );
    },
  );

  await check(
    'keys.js: loadSigningKeys rejects a non-EC or non-P-256 key loudly rather than silently accepting it',
    async () => {
      const tmpDir = fs.mkdtempSync(
        path.join(require('node:os').tmpdir(), 'verdaccio-attestations-rsa-'),
      );
      try {
        const {privateKey} = crypto.generateKeyPairSync('rsa', {
          modulusLength: 2048,
        });
        fs.writeFileSync(
          path.join(tmpDir, 'tls.key'),
          privateKey.export({type: 'pkcs1', format: 'pem'}),
        );
        // loadSigningKey reads tls.crt (just to get an X509Certificate
        // instance) before checking the private key's own
        // asymmetricKeyType -- an unrelated-but-valid cert is enough here,
        // since the EC-type check throws before the cert's own public key is
        // ever used for anything. Reuses the real fixture's own cert file
        // rather than generating a fresh matching one.
        fs.copyFileSync(
          path.join(SIGNING_KEY_FIXTURE_DIR, 'tls.crt'),
          path.join(tmpDir, 'tls.crt'),
        );
        assert.throws(() => loadSigningKeys([tmpDir]), /only ECDSA P-256/);
      } finally {
        fs.rmSync(tmpDir, {recursive: true, force: true});
      }
    },
  );

  await check(
    "keys.js: loadSigningKeys rejects a tls.key that doesn't belong to tls.crt",
    async () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'att-keypair-'));
      try {
        fs.copyFileSync(
          path.join(SIGNING_KEY_FIXTURE_DIR, 'tls.crt'),
          path.join(dir, 'tls.crt'),
        );
        const {privateKey} = crypto.generateKeyPairSync('ec', {
          namedCurve: 'P-256',
        });
        fs.writeFileSync(
          path.join(dir, 'tls.key'),
          privateKey.export({type: 'pkcs8', format: 'pem'}),
        );
        assert.throws(() => loadSigningKeys([dir]), /does not match/);
      } finally {
        fs.rmSync(dir, {recursive: true, force: true});
      }
    },
  );

  await check(
    'keys.js: normalizeUpstreamKeysResponse filters malformed entries and defaults keytype/scheme',
    async () => {
      const normalized = normalizeUpstreamKeysResponse({
        keys: [
          {
            keyid: 'SHA256:abc',
            key: 'base64stuff',
            expires: '2030-01-01T00:00:00Z',
          },
          {keyid: 'SHA256:def', key: 'otherbase64'}, // no expires/keytype/scheme -- must default
          {keyid: 'SHA256:missing-key'}, // no `key` -- must be dropped
          {key: 'no-keyid'}, // no `keyid` -- must be dropped
          null,
        ],
      });
      assert.equal(normalized.length, 2);
      assert.deepEqual(normalized[0], {
        keyid: 'SHA256:abc',
        expires: '2030-01-01T00:00:00Z',
        keytype: 'ecdsa-sha2-nistp256',
        scheme: 'ecdsa-sha2-nistp256',
        key: 'base64stuff',
      });
      assert.equal(normalized[1].expires, null);

      assert.deepEqual(normalizeUpstreamKeysResponse({}), []);
      assert.deepEqual(normalizeUpstreamKeysResponse(null), []);
    },
  );

  await check(
    'constructor: sigstore.signingKeys must be an array, rejected loudly otherwise',
    async () => {
      assert.throws(
        () =>
          makeAttestations({sigstore: {signingKeys: SIGNING_KEY_FIXTURE_DIR}}),
        /sigstore\.signingKeys must be an array/,
      );
    },
  );

  // --- Own-key signing: gated strictly on trustedPublishers configured AND matched ---

  await check(
    'publish-time signing: signs with our own key only when trustedPublishers is configured AND the identity matched',
    async () => {
      __resetSharedStateForTests();
      const storage = makeFakeStorage();
      const plugin = makeAttestations({
        sigstore: {
          trustedPublishers: [
            {subjectAlternativeName: 'https://github.com/actions/toolkit/**'},
          ],
          signingKeys: [SIGNING_KEY_FIXTURE_DIR],
        },
      });
      plugin.register_middlewares(
        {use() {}, get() {}},
        {config: {}},
        wrapAsTopLevelStorage(storage),
      );

      const bundle = realProvenanceBundle();
      const body = {
        _attachments: {
          'core-3.0.1.tgz': {data: REAL_TARBALL_DATA},
          'core-3.0.1.tgz.sigstore': {
            data: JSON.stringify(bundle), // raw string, matching real npm/Yarn -- NOT base64
          },
        },
        versions: {
          '3.0.1': {version: '3.0.1', dist: {integrity: REAL_PKG.integrity}},
        },
      };
      const req = makeFakeReq(body);
      const res = makeFakeRes(201);
      await plugin._interceptPublish(req, res, '@actions/core');
      res._triggerFinish();
      await plugin.whenAllBackgroundWorkSettles();

      const versionMeta = body.versions['3.0.1'];
      assert.equal(
        versionMeta.dist.attestations.verified,
        true,
        versionMeta.dist.attestations.reason,
      );
      assert.equal(versionMeta.dist.signatures.length, 1);
      const {keyid, sig} = versionMeta.dist.signatures[0];
      assert.equal(keyid, plugin.signingKeys[0].keyid);

      const pem = `-----BEGIN PUBLIC KEY-----\n${plugin.signingKeys[0].publicKeyEntry.key.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----\n`;
      const message = `@actions/core@3.0.1:${REAL_PKG.integrity}`;
      const verifier = crypto.createVerify('SHA256');
      verifier.write(message);
      verifier.end();
      assert.equal(verifier.verify(pem, sig, 'base64'), true);
    },
  );

  await check(
    'publish-time signing: does NOT sign when trustedPublishers is not configured, even though the attestation verified',
    async () => {
      __resetSharedStateForTests();
      const storage = makeFakeStorage();
      const plugin = makeAttestations({
        sigstore: {signingKeys: [SIGNING_KEY_FIXTURE_DIR]},
      });
      plugin.register_middlewares(
        {use() {}, get() {}},
        {config: {}},
        wrapAsTopLevelStorage(storage),
      );

      const bundle = realProvenanceBundle();
      const body = {
        _attachments: {
          'core-3.0.1.tgz': {data: REAL_TARBALL_DATA},
          'core-3.0.1.tgz.sigstore': {
            data: JSON.stringify(bundle), // raw string, matching real npm/Yarn -- NOT base64
          },
        },
        versions: {
          '3.0.1': {version: '3.0.1', dist: {integrity: REAL_PKG.integrity}},
        },
      };
      const req = makeFakeReq(body);
      const res = makeFakeRes(201);
      await plugin._interceptPublish(req, res, '@actions/core');
      res._triggerFinish();
      await plugin.whenAllBackgroundWorkSettles();

      const versionMeta = body.versions['3.0.1'];
      assert.equal(
        versionMeta.dist.attestations.verified,
        true,
        versionMeta.dist.attestations.reason,
      );
      assert.equal(versionMeta.dist.signatures, undefined);
    },
  );

  await check(
    'publish-time signing: does NOT sign when trustedPublishers is configured but the identity did not match',
    async () => {
      __resetSharedStateForTests();
      const storage = makeFakeStorage();
      const plugin = makeAttestations({
        sigstore: {
          trustedPublishers: [
            {subjectAlternativeName: 'https://github.com/some-other-org/**'},
          ],
          signingKeys: [SIGNING_KEY_FIXTURE_DIR],
        },
      });
      plugin.register_middlewares(
        {use() {}, get() {}},
        {config: {}},
        wrapAsTopLevelStorage(storage),
      );

      const bundle = realProvenanceBundle();
      const body = {
        _attachments: {
          'core-3.0.1.tgz': {data: REAL_TARBALL_DATA},
          'core-3.0.1.tgz.sigstore': {
            data: JSON.stringify(bundle), // raw string, matching real npm/Yarn -- NOT base64
          },
        },
        versions: {
          '3.0.1': {version: '3.0.1', dist: {integrity: REAL_PKG.integrity}},
        },
      };
      const req = makeFakeReq(body);
      const res = makeFakeRes(201);
      await plugin._interceptPublish(req, res, '@actions/core');
      res._triggerFinish();
      await plugin.whenAllBackgroundWorkSettles();

      const versionMeta = body.versions['3.0.1'];
      assert.equal(versionMeta.dist.attestations.verified, false);
      assert.equal(versionMeta.dist.signatures, undefined);
    },
  );

  await check(
    'publish-time signing: no signingKeys configured at all means no dist.signatures, even with trustedPublishers matched',
    async () => {
      __resetSharedStateForTests();
      const storage = makeFakeStorage();
      const plugin = makeAttestations({
        sigstore: {
          trustedPublishers: [
            {subjectAlternativeName: 'https://github.com/actions/toolkit/**'},
          ],
        },
      });
      plugin.register_middlewares(
        {use() {}, get() {}},
        {config: {}},
        wrapAsTopLevelStorage(storage),
      );

      const bundle = realProvenanceBundle();
      const body = {
        _attachments: {
          'core-3.0.1.tgz': {data: REAL_TARBALL_DATA},
          'core-3.0.1.tgz.sigstore': {
            data: JSON.stringify(bundle), // raw string, matching real npm/Yarn -- NOT base64
          },
        },
        versions: {
          '3.0.1': {version: '3.0.1', dist: {integrity: REAL_PKG.integrity}},
        },
      };
      const req = makeFakeReq(body);
      const res = makeFakeRes(201);
      await plugin._interceptPublish(req, res, '@actions/core');
      res._triggerFinish();
      await plugin.whenAllBackgroundWorkSettles();

      const versionMeta = body.versions['3.0.1'];
      assert.equal(
        versionMeta.dist.attestations.verified,
        true,
        versionMeta.dist.attestations.reason,
      );
      assert.equal(versionMeta.dist.signatures, undefined);
    },
  );

  // --- GET /-/npm/v1/keys route ---

  await check(
    'GET /-/npm/v1/keys: serves our own configured signing key(s), unconditionally',
    async () => {
      __resetSharedStateForTests();
      const plugin = makeAttestations({
        sigstore: {signingKeys: [SIGNING_KEY_FIXTURE_DIR]},
      });
      let routeHandler;
      const fakeApp = {
        use() {},
        get(routePath, handler) {
          if (routePath === '/-/npm/v1/keys') routeHandler = handler;
        },
      };
      plugin.register_middlewares(
        fakeApp,
        {config: {}},
        wrapAsTopLevelStorage(makeFakeStorage()),
      );
      assert.ok(
        routeHandler,
        'GET /-/npm/v1/keys must be registered unconditionally',
      );

      const res = {
        status(code) {
          this.statusCode = code;
          return this;
        },
        json(body) {
          this.body = body;
          return this;
        },
      };
      routeHandler({}, res);
      assert.equal(res.statusCode, 200);
      assert.equal(res.body.keys.length, 1);
      assert.equal(res.body.keys[0].keyid, plugin.signingKeys[0].keyid);
    },
  );

  await check(
    'GET /-/npm/v1/keys: with no signingKeys and no relayed upstream keys, serves an empty list rather than erroring',
    async () => {
      __resetSharedStateForTests();
      const plugin = makeAttestations({});
      let routeHandler;
      const fakeApp = {
        use() {},
        get(routePath, handler) {
          if (routePath === '/-/npm/v1/keys') routeHandler = handler;
        },
      };
      plugin.register_middlewares(
        fakeApp,
        {config: {}},
        wrapAsTopLevelStorage(makeFakeStorage()),
      );

      const res = {
        status(code) {
          this.statusCode = code;
          return this;
        },
        json(body) {
          this.body = body;
          return this;
        },
      };
      routeHandler({}, res);
      assert.equal(res.statusCode, 200);
      assert.deepEqual(res.body.keys, []);
    },
  );

  // --- Upstream registry-key relay: unconditional, persisted, warm-started ---

  await check(
    'upstream key relay: fetches GET /-/npm/v1/keys from every configured uplink unconditionally (no fetchUpstream, no sigstore config at all)',
    async () => {
      __resetSharedStateForTests();
      const requestedUrls = [];
      const upstreamKeysResponse = {
        keys: [
          {
            keyid: 'SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA',
            expires: null,
            keytype: 'ecdsa-sha2-nistp256',
            scheme: 'ecdsa-sha2-nistp256',
            key: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfakekeymaterial==',
          },
        ],
      };
      const plugin = makeAttestations(
        {}, // no fetchUpstream, no sigstore config -- must still relay
        {
          fetch: async url => {
            requestedUrls.push(url);
            return {ok: true, json: async () => upstreamKeysResponse};
          },
        },
      );
      plugin.register_middlewares(
        {use() {}, get() {}},
        {config: {uplinks: {npmjs: {url: 'https://registry.npmjs.org'}}}},
        wrapAsTopLevelStorage(makeFakeStorage()),
      );
      await plugin.whenAllBackgroundWorkSettles();

      assert.equal(requestedUrls.length, 1);
      assert.equal(
        requestedUrls[0],
        'https://registry.npmjs.org/-/npm/v1/keys',
      );
      assert.equal(plugin._upstreamKeysCache.size, 1);
      assert.deepEqual(
        plugin._upstreamKeysCache.get(
          'SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA',
        ),
        {
          source: 'https://registry.npmjs.org',
          entry: upstreamKeysResponse.keys[0],
        },
      );
    },
  );

  await check(
    'upstream key relay: with no uplinks configured at all, never calls fetch',
    async () => {
      __resetSharedStateForTests();
      let fetchCalls = 0;
      const plugin = makeAttestations(
        {},
        {
          fetch: async () => {
            fetchCalls += 1;
            throw new Error('must not be called');
          },
        },
      );
      plugin.register_middlewares(
        {use() {}, get() {}},
        {config: {}}, // no uplinks
        wrapAsTopLevelStorage(makeFakeStorage()),
      );
      await plugin.whenAllBackgroundWorkSettles();
      assert.equal(fetchCalls, 0);
    },
  );

  await check(
    'upstream key relay: relayed keys are combined with our own signing key(s) at GET /-/npm/v1/keys',
    async () => {
      __resetSharedStateForTests();
      const upstreamKeysResponse = {
        keys: [
          {
            keyid: 'SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA',
            key: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfakekeymaterial==',
          },
        ],
      };
      const plugin = makeAttestations(
        {sigstore: {signingKeys: [SIGNING_KEY_FIXTURE_DIR]}},
        {
          fetch: async () => ({
            ok: true,
            json: async () => upstreamKeysResponse,
          }),
        },
      );
      let routeHandler;
      const fakeApp = {
        use() {},
        get(routePath, handler) {
          if (routePath === '/-/npm/v1/keys') routeHandler = handler;
        },
      };
      plugin.register_middlewares(
        fakeApp,
        {config: {uplinks: {npmjs: {url: 'https://registry.npmjs.org'}}}},
        wrapAsTopLevelStorage(makeFakeStorage()),
      );
      await plugin.whenAllBackgroundWorkSettles();

      const res = {
        status(code) {
          this.statusCode = code;
          return this;
        },
        json(body) {
          this.body = body;
          return this;
        },
      };
      routeHandler({}, res);
      const keyids = res.body.keys.map(k => k.keyid).sort();
      assert.deepEqual(
        keyids,
        [
          'SHA256:5DWUjCF8n7XXCTUYmhTlpB1aLzOfzVxQorKHSpgH3do',
          'SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA',
        ].sort(),
      );
    },
  );

  await check(
    'upstream key relay: relayed keys are held in memory only, never written to storage',
    async () => {
      __resetSharedStateForTests();
      const storage = makeFakeStorage();
      const plugin = makeAttestations(
        {},
        {
          fetch: async () => ({
            ok: true,
            json: async () => ({
              keys: [{keyid: 'SHA256:memory-only', key: 'ZmFrZQ=='}],
            }),
          }),
        },
      );
      plugin.register_middlewares(
        {use() {}, get() {}},
        {config: {uplinks: {npmjs: {url: 'https://registry.npmjs.org'}}}},
        wrapAsTopLevelStorage(storage),
      );
      await plugin.whenAllBackgroundWorkSettles();
      assert.equal(plugin._upstreamKeysCache.size, 1);
      assert.equal(storage.files.size, 0);
    },
  );

  await check(
    "upstream key relay: an uplink offering one of this registry's own keyids is ignored, and GET /-/npm/v1/keys lists only our key for it",
    async () => {
      __resetSharedStateForTests();
      const [ownKey] = loadSigningKeys([SIGNING_KEY_FIXTURE_DIR]);
      const plugin = makeAttestations(
        {sigstore: {signingKeys: [SIGNING_KEY_FIXTURE_DIR]}},
        {
          fetch: async () => ({
            ok: true,
            json: async () => ({
              keys: [{keyid: ownKey.keyid, key: 'YXR0YWNrZXIta2V5'}],
            }),
          }),
        },
      );
      let routeHandler;
      plugin.register_middlewares(
        {
          use() {},
          get(routePath, handler) {
            if (routePath === '/-/npm/v1/keys') routeHandler = handler;
          },
        },
        {config: {uplinks: {npmjs: {url: 'https://registry.npmjs.org'}}}},
        wrapAsTopLevelStorage(makeFakeStorage()),
      );
      await plugin.whenAllBackgroundWorkSettles();
      assert.equal(plugin._upstreamKeysCache.size, 0);

      const res = makeRecordingRes();
      routeHandler({}, res);
      assert.deepEqual(
        res.body.keys.map(k => k.key),
        [ownKey.publicKeyEntry.key],
      );
    },
  );

  await check(
    'upstream key relay: the first uplink to supply a keyid keeps it; a second uplink offering a different key for it is ignored',
    async () => {
      __resetSharedStateForTests();
      const warnings = [];
      const plugin = new Attestations(
        {},
        {
          logger: {...NOOP_LOGGER, warn: (obj, msg) => warnings.push(msg)},
          fetch: async url => ({
            ok: true,
            json: async () => ({
              keys: [
                {
                  keyid: 'SHA256:shared-keyid',
                  key: url.includes('first') ? 'Zmlyc3Q=' : 'c2Vjb25k',
                },
              ],
            }),
          }),
        },
      );
      plugin.register_middlewares(
        {use() {}, get() {}},
        {
          config: {
            uplinks: {
              a: {url: 'https://first.example'},
              b: {url: 'https://second.example'},
            },
          },
        },
        wrapAsTopLevelStorage(makeFakeStorage()),
      );
      await plugin.whenAllBackgroundWorkSettles();

      // A later refresh doesn't hand it over either.
      await plugin._refreshUpstreamKeys();
      const kept = plugin._upstreamKeysCache.get('SHA256:shared-keyid');
      assert.equal(kept.source, 'https://first.example');
      assert.equal(kept.entry.key, 'Zmlyc3Q=');
      assert.ok(
        warnings.some(m => m.includes('offered a different key')),
        'the conflict must be logged',
      );
    },
  );

  await check(
    'GET /-/npm/v1/keys lists our own signing key(s) before any relayed upstream key',
    async () => {
      __resetSharedStateForTests();
      const [ownKey] = loadSigningKeys([SIGNING_KEY_FIXTURE_DIR]);
      const plugin = makeAttestations(
        {sigstore: {signingKeys: [SIGNING_KEY_FIXTURE_DIR]}},
        {
          fetch: async () => ({
            ok: true,
            json: async () => ({
              keys: [{keyid: 'SHA256:aaaa-sorts-first', key: 'dXBzdHJlYW0='}],
            }),
          }),
        },
      );
      let routeHandler;
      plugin.register_middlewares(
        {
          use() {},
          get(routePath, handler) {
            if (routePath === '/-/npm/v1/keys') routeHandler = handler;
          },
        },
        {config: {uplinks: {npmjs: {url: 'https://registry.npmjs.org'}}}},
        wrapAsTopLevelStorage(makeFakeStorage()),
      );
      await plugin.whenAllBackgroundWorkSettles();

      const res = makeRecordingRes();
      routeHandler({}, res);
      assert.deepEqual(
        res.body.keys.map(k => k.keyid),
        [ownKey.keyid, 'SHA256:aaaa-sorts-first'],
      );
    },
  );

  await check(
    "upstream key relay: an upstream fetch failure for one uplink does not prevent another uplink's keys from being relayed",
    async () => {
      __resetSharedStateForTests();
      const plugin = makeAttestations(
        {},
        {
          fetch: async url => {
            if (url.includes('flaky')) throw new Error('ECONNREFUSED');
            return {
              ok: true,
              json: async () => ({
                keys: [{keyid: 'SHA256:from-good-uplink', key: 'Z29vZC1rZXk='}],
              }),
            };
          },
        },
      );
      plugin.register_middlewares(
        {use() {}, get() {}},
        {
          config: {
            uplinks: {
              flaky: {url: 'https://flaky.example.com'},
              good: {url: 'https://good.example.com'},
            },
          },
        },
        wrapAsTopLevelStorage(makeFakeStorage()),
      );
      await plugin.whenAllBackgroundWorkSettles();
      assert.equal(plugin._upstreamKeysCache.size, 1);
      assert.ok(plugin._upstreamKeysCache.has('SHA256:from-good-uplink'));
    },
  );

  // --- body-buffering middleware (workaround for verdaccio/verdaccio#1912) ---

  await check(
    "buffering middleware: a PUT with a JSON content-type gets req.body/req._body populated, before this plugin's own publish-intercepting middleware even runs",
    async () => {
      const plugin = makeAttestations({});
      const handlers = [];
      plugin.register_middlewares(
        {use: fn => handlers.push(fn), get() {}},
        {config: {}},
        wrapAsTopLevelStorage(makeFakeStorage()),
      );
      // handlers[0] is the offline-restriction context middleware, [1] is
      // this new buffering one, [2] is the existing publish-intercepting
      // middleware -- run just the first two here.
      const [, bufferHandler] = handlers;

      const {Readable} = require('node:stream');
      const req = new Readable({read() {}});
      req.method = 'PUT';
      const payload = {versions: {'1.0.0': {version: '1.0.0'}}};
      // body-parser treats a request with neither content-length nor
      // transfer-encoding as bodiless; every real publish sends one.
      req.headers = {
        'content-type': 'application/json',
        'content-length': String(Buffer.byteLength(JSON.stringify(payload))),
      };
      process.nextTick(() => {
        req.push(JSON.stringify(payload));
        req.push(null);
      });

      await new Promise((resolve, reject) => {
        bufferHandler(req, {}, err => (err ? reject(err) : resolve()));
      });
      assert.equal(req._body, true);
      assert.deepEqual(req.body, payload);
    },
  );

  await check(
    'buffering middleware: skips entirely if an earlier middleware already populated req._body',
    async () => {
      const plugin = makeAttestations({});
      const handlers = [];
      plugin.register_middlewares(
        {use: fn => handlers.push(fn), get() {}},
        {config: {}},
        wrapAsTopLevelStorage(makeFakeStorage()),
      );
      const [, bufferHandler] = handlers;

      const {Readable} = require('node:stream');
      const req = new Readable({read() {}});
      req.method = 'PUT';
      req.headers = {'content-type': 'application/json'};
      req._body = true;
      req.body = {alreadySetByAnotherPlugin: true};
      process.nextTick(() => {
        req.push('{"versions":{}}');
        req.push(null);
      });

      await new Promise((resolve, reject) => {
        bufferHandler(req, {}, err => (err ? reject(err) : resolve()));
      });
      assert.deepEqual(req.body, {alreadySetByAnotherPlugin: true});
    },
  );

  await check(
    'end-to-end: the buffering middleware prevents the exact stream-draining race a real, unmodified Verdaccio log.js causes, when this plugin is the first (or only) one reading the body',
    async () => {
      // Mirrors @verdaccio/middleware's own log.js exactly (confirmed
      // directly against its real, installed source) -- see
      // verdaccio-security-filter's identical test for the full analysis
      // of why an additional, unrelated async plugin ahead of this one is
      // deliberately not also simulated here (that combination is
      // unfixable by any single plugin; verdaccio-oidc-auth's own copy of
      // this same fix is what protects that case, by buffering before its
      // own async work rather than after).
      function verdaccioLogMiddlewareMirror(req, res, next) {
        let bytesin = 0;
        req.on('data', chunk => {
          bytesin += chunk.length;
        });
        next();
      }

      const plugin = makeAttestations({});
      const storage = makeFakeStorage();
      const handlers = [];
      plugin.register_middlewares(
        {use: fn => handlers.push(fn), get() {}},
        {config: {}},
        wrapAsTopLevelStorage(storage),
      );
      const allHandlers = [verdaccioLogMiddlewareMirror, ...handlers];

      const app = makeApp();
      app.use((req, res, next) => {
        let index = 0;
        const dispatch = err => {
          if (err) return next(err);
          const handler = allHandlers[index++];
          if (!handler) return next();
          handler(req, res, dispatch);
        };
        dispatch();
      });
      app.put('/:package', (req, res) => {
        res.status(201).json({ok: true, versions: !!req.body?.versions});
      });

      const server = await new Promise(resolve => {
        const s = app.listen(0, () => resolve(s));
      });
      try {
        const port = server.address().port;
        const payload = JSON.stringify({
          versions: {'1.0.0': {version: '1.0.0'}},
          filler: 'x'.repeat(75000), // realistic publish-with-provenance size
        });

        const response = await fetch(`http://localhost:${port}/pkg`, {
          method: 'PUT',
          headers: {'content-type': 'application/json'},
          body: payload,
        });
        const json = await response.json();
        assert.equal(
          response.status,
          201,
          `expected the publish to succeed despite log.js's own listener; got: ${JSON.stringify(json)}`,
        );
        assert.ok(json.versions);
      } finally {
        server.close();
      }
    },
  );

  console.log(results.join('\n'));
  console.log(`\n${passed} check(s) passed.`);
  if (results.some(r => r.startsWith('FAIL'))) process.exitCode = 1;
}

main();
