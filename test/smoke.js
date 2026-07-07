'use strict';

const assert = require('node:assert/strict');
const {EventEmitter} = require('node:events');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const {
  Attestations,
  requestContext,
  __resetSharedStateForTests,
} = require('../index.js');
const {verifyBundle, verifyAttestationsResponse} = require('../verify.js');

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
function realProvenanceBundle() {
  return REAL_ATTESTATIONS.attestations.find(a =>
    a.predicateType.includes('slsa.dev'),
  ).bundle;
}
function realKeyedBundle() {
  return REAL_ATTESTATIONS.attestations.find(
    a => !a.predicateType.includes('slsa.dev'),
  ).bundle;
}

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
function makeFakeReq(body) {
  return {
    body,
    protocol: 'http',
    get: header => (header === 'host' ? 'localhost:4873' : undefined),
  };
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
        {...REAL_PKG, integrity: 'sha512-' + 'A'.repeat(88)},
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
        block: [
          {'some-pkg': {versions: '1.0.0', strategy: 'replace'}},
          'other-pkg',
        ],
      });
      const withStrategy = makePackageInfo('some-pkg', {
        '0.9.0': {
          version: '0.9.0',
          dist: {
            integrity: 'sha512-good',
            attestations: {verified: true},
            tarball: 'good.tgz',
          },
        },
        '1.0.0': {version: '1.0.0', dist: {integrity: 'sha512-bad'}},
      });
      const replaced = await plugin.filter_metadata(withStrategy);
      assert.ok('1.0.0' in replaced.versions, 'replaced version keeps its key');
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

  // --- filter_metadata: fast tier only, background verification for the rest ---

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
    'filter_metadata leaves a version alone whose packument-embedded verdict is verified:true',
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
      assert.ok('1.0.0' in result.versions);
    },
  );

  await check(
    'filter_metadata blocks a version whose packument-embedded verdict is verified:false',
    async () => {
      const plugin = makeAttestations({block: ['**']});
      const pkg = makePackageInfo('some-pkg', {
        '1.0.0': {
          version: '1.0.0',
          dist: {
            integrity: 'sha512-x',
            attestations: {verified: false, reason: 'bad sig', url: '/x'},
          },
        },
      });
      const result = await plugin.filter_metadata(pkg);
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
    'a never-before-seen version fails closed IMMEDIATELY (no network wait) and resolves for real in the background',
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

      const pkg = makePackageInfo('@actions/core', {
        '3.0.1': {version: '3.0.1', dist: {integrity: REAL_PKG.integrity}},
      });

      await asOnlineRequest(async () => {
        const first = await plugin.filter_metadata(structuredClone(pkg));
        assert.ok(
          !('3.0.1' in first.versions),
          'must be blocked on the very first read -- there is no way to have a real verdict yet without waiting on the network',
        );

        await plugin.whenAllBackgroundWorkSettles();

        const second = await plugin.filter_metadata(structuredClone(pkg));
        assert.ok(
          '3.0.1' in second.versions,
          'the background resolution should have verified it by now',
        );
        assert.equal(fetchCalls, 1);
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

      const pkg = makePackageInfo('multi-ver-pkg', {
        '1.0.0': {version: '1.0.0', dist: {integrity: 'sha512-a'}},
        '2.0.0': {version: '2.0.0', dist: {integrity: 'sha512-b'}},
      });
      await asOnlineRequest(async () => {
        await plugin.filter_metadata(pkg); // kicks off two background resolutions
        await plugin.whenAllBackgroundWorkSettles();
      });
      // If these ran sequentially, the second fetch could only start after
      // the first's 'end' -- concurrent execution means both starts land
      // before either end.
      assert.deepEqual(
        callOrder.slice(0, 2).map(c => c.split(':')[0]),
        ['start', 'start'],
      );
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
      await asOnlineRequest(async () => {
        await podOne.filter_metadata(structuredClone(pkg));
        await podOne.whenAllBackgroundWorkSettles();
      });
      assert.equal(fetchCalls, 1);

      // A brand new plugin instance -- fresh in-memory _verdictCache, same
      // underlying storage -- simulates a pod restart.
      const podTwo = makeAttestations(
        {block: ['**'], fetchUpstream: true},
        {fetch: fakeFetch},
      );
      podTwo._storage = wrapAsTopLevelStorage(sharedStorage);
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
          fetch: async () => {
            fetchCalls += 1;
            return {ok: true, json: async () => REAL_ATTESTATIONS};
          },
          config: {
            middlewares: {
              '@fortmesa/verdaccio-offline-enforcer': {offline: ['ci-bot']},
            },
          },
        },
      );

      const app = express();
      // Sets req.remote_user BEFORE register_middlewares' own ALS-populating
      // middleware runs, same as a real auth plugin would -- registration
      // order matters here, unlike the plugin's own internal middlewares.
      app.use((req, res, next) => {
        req.remote_user = currentUser;
        next();
      });
      plugin.register_middlewares(
        app,
        {config: {}},
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

      const server = await new Promise(resolve => {
        const s = app.listen(0, () => resolve(s));
      });
      try {
        const port = server.address().port;

        // Restricted identity's request: filter_metadata's fast tier fails
        // closed AND the background resolution it kicks off must never
        // actually reach the network, even though fetchUpstream is true.
        currentUser = {name: 'ci-bot', real_groups: []};
        await fetch(`http://localhost:${port}/x`);
        await plugin.whenAllBackgroundWorkSettles();
        assert.equal(
          fetchCalls,
          0,
          "an offline-restricted identity's request must never trigger a live upstream fetch",
        );

        // A DIFFERENT, non-restricted identity's request for the SAME
        // package (a fresh plugin instance avoids the first identity's
        // now-cached "not yet verified" verdict masking this).
        const plugin2 = new Attestations(
          {block: ['**'], fetchUpstream: true},
          {
            logger: NOOP_LOGGER,
            fetch: async () => {
              fetchCalls += 1;
              return {ok: true, json: async () => REAL_ATTESTATIONS};
            },
            config: {
              middlewares: {
                '@fortmesa/verdaccio-offline-enforcer': {offline: ['ci-bot']},
              },
            },
          },
        );
        const app2 = express();
        app2.use((req, res, next) => {
          req.remote_user = {name: 'a-developer', real_groups: []};
          next();
        });
        plugin2.register_middlewares(
          app2,
          {config: {}},
          wrapAsTopLevelStorage(makeFakeStorage()),
        );
        app2.get('/:pkg', (req, res, next) => {
          const pkg = makePackageInfo('@actions/core', {
            '3.0.1': {version: '3.0.1', dist: {integrity: REAL_PKG.integrity}},
          });
          plugin2
            .filter_metadata(pkg)
            .then(result => res.json(result))
            .catch(next);
        });
        const server2 = await new Promise(resolve => {
          const s = app2.listen(0, () => resolve(s));
        });
        try {
          const port2 = server2.address().port;
          await fetch(`http://localhost:${port2}/x`);
          await plugin2.whenAllBackgroundWorkSettles();
          assert.equal(
            fetchCalls,
            1,
            "a non-restricted identity's request must be able to trigger the live upstream fetch",
          );
        } finally {
          server2.close();
        }
      } finally {
        server.close();
      }
    },
  );

  // --- proxy support, mirroring verdaccio-audit's ProxyAudit exactly ---

  await check('_requestAgent uses a plain https.Agent by default', () => {
    const plugin = makeAttestations({});
    plugin._auth = {config: {}};
    const agent = plugin._requestAgent();
    assert.equal(agent.constructor.name, 'Agent');
  });

  await check(
    '_requestAgent uses HttpsProxyAgent when auth.config.https_proxy is set',
    () => {
      const plugin = makeAttestations({});
      plugin._auth = {config: {https_proxy: 'http://proxy.example.com:8080'}};
      const agent = plugin._requestAgent();
      assert.equal(agent.constructor.name, 'HttpsProxyAgent');
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
          '@actions/core-3.0.1.tgz': {data: 'ZmFrZQ=='},
          '@actions/core-3.0.1.sigstore': {
            data: Buffer.from(JSON.stringify(bundle)).toString('base64'),
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
          '@actions/core-3.0.1.tgz': {data: 'ZmFrZQ=='},
          '@actions/core-3.0.1.sigstore': {
            data: Buffer.from(JSON.stringify(bundle)).toString('base64'),
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
          '@actions/core-3.0.1.tgz': {data: 'ZmFrZQ=='},
          '@actions/core-3.0.1.sigstore': {
            data: Buffer.from(JSON.stringify(bundle)).toString('base64'),
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

      const tamperedBundle = realProvenanceBundle();
      const body = {
        name: '@actions/core',
        versions: {
          '3.0.1': {
            version: '3.0.1',
            dist: {integrity: 'sha512-' + 'A'.repeat(88)},
          },
        },
        _attachments: {
          '@actions/core-3.0.1.tgz': {data: 'ZmFrZQ=='},
          '@actions/core-3.0.1.sigstore': {
            data: Buffer.from(JSON.stringify(tamperedBundle)).toString(
              'base64',
            ),
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

  // --- GET /-/npm/v1/attestations/:pkgAtVersion ---

  await check(
    'serves an already-locally-stored verified bundle without any upstream fetch',
    async () => {
      const plugin = makeAttestations({}, {fetch: makeFakeFetch({})});
      const storage = makeFakeStorage();
      plugin._storage = wrapAsTopLevelStorage(storage);
      await plugin._storeVerdictAndBundle(
        '@actions/core',
        '3.0.1',
        realProvenanceBundle(),
        {verified: true},
      );

      let statusCode;
      let jsonBody;
      const res = {
        status(code) {
          statusCode = code;
          return this;
        },
        json(body) {
          jsonBody = body;
          return this;
        },
        end() {},
      };
      await plugin._handleGetAttestations(
        {params: {pkgAtVersion: '@actions%2Fcore@3.0.1'}},
        res,
      );
      assert.equal(statusCode, 200);
      assert.ok(jsonBody.attestations[0].bundle);
    },
  );

  await check(
    'with fetchUpstream disabled (default), a genuine miss 404s without attempting a fetch',
    async () => {
      const plugin = makeAttestations({}, {fetch: makeFakeFetch({})}); // any call should throw
      plugin._storage = wrapAsTopLevelStorage(makeFakeStorage());

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
      await plugin._handleGetAttestations(
        {params: {pkgAtVersion: '@actions%2Fcore@3.0.1'}},
        res,
      );
      assert.equal(statusCode, 404);
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
            return {ok: true, json: async () => REAL_ATTESTATIONS};
          },
        },
      );
      const storage = makeFakeStorage();
      plugin._storage = wrapAsTopLevelStorage(storage);

      let statusCode;
      let jsonBody;
      const res = {
        status(code) {
          statusCode = code;
          return this;
        },
        json(body) {
          jsonBody = body;
          return this;
        },
        end() {},
      };
      await asOnlineRequest(() =>
        plugin._handleGetAttestations(
          {params: {pkgAtVersion: '@actions%2Fcore@3.0.1'}},
          res,
        ),
      );
      assert.equal(statusCode, 200);
      assert.equal(fetchCalls, 1);
      assert.deepEqual(jsonBody, REAL_ATTESTATIONS);
      assert.equal(
        storage.files.size,
        0,
        'a bare GET has no dist.integrity to verify against, so nothing gets cached',
      );
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
            return {ok: true, json: async () => REAL_ATTESTATIONS};
          },
        },
      );
      plugin._storage = wrapAsTopLevelStorage(makeFakeStorage());

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
      await requestContext.run({offlineRestricted: true}, () =>
        plugin._handleGetAttestations(
          {params: {pkgAtVersion: '@actions%2Fcore@3.0.1'}},
          res,
        ),
      );
      assert.equal(
        fetchCalls,
        0,
        "an offline-restricted identity's request to this route must never trigger a live upstream fetch",
      );
      assert.equal(statusCode, 404);
    },
  );

  await check(
    '404s when neither local storage nor (disabled) upstream has anything',
    async () => {
      const plugin = makeAttestations({}, {fetch: makeFakeFetch({})});
      plugin._storage = wrapAsTopLevelStorage(makeFakeStorage());

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
      await plugin._handleGetAttestations(
        {params: {pkgAtVersion: 'nonexistent-pkg@1.0.0'}},
        res,
      );
      assert.equal(statusCode, 404);
    },
  );

  // --- true end-to-end: a real Express app, real HTTP requests, real routing ---

  await check(
    'end-to-end: a real PUT publish request with a .sigstore attachment is intercepted through actual Express routing',
    async () => {
      const plugin = makeAttestations({});
      const storage = makeFakeStorage();
      const app = express();
      plugin.register_middlewares(
        app,
        {config: {}},
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
            '@actions/core-3.0.1.tgz': {data: 'ZmFrZQ=='},
            '@actions/core-3.0.1.sigstore': {
              data: Buffer.from(JSON.stringify(bundle)).toString('base64'),
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
        assert.equal(json.attestations.verified, true);
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
        realProvenanceBundle(),
        {verified: true},
      );

      const app = express();
      plugin.register_middlewares(
        app,
        {config: {}},
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
        realProvenanceBundle(),
        {verified: true},
      );
      assert.ok(
        storage.files.has('@actions/core\x00@actions-core-3.0.1.attestation'),
        'sanity check: the verdict is actually there before the delete',
      );

      const app = express();
      plugin.register_middlewares(
        app,
        {config: {}},
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

      const app = express();
      plugin.register_middlewares(
        app,
        {config: {}},
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
        realProvenanceBundle(),
        {verified: true},
      );

      const app = express();
      plugin.register_middlewares(
        app,
        {config: {}},
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
            return {ok: true, json: async () => REAL_ATTESTATIONS};
          },
        },
      );
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
        assert.ok(!('3.0.1' in first.versions));
        await plugin.whenAllBackgroundWorkSettles();

        const second = await plugin.filter_metadata(structuredClone(pkg));
        assert.ok(
          '3.0.1' in second.versions,
          'the in-memory _verdictCache alone must be enough to answer the second check',
        );
        assert.equal(fetchCalls, 1, 'must not have crashed or re-fetched');
      });
    },
  );

  console.log(results.join('\n'));
  console.log(`\n${passed} check(s) passed.`);
  if (results.some(r => r.startsWith('FAIL'))) process.exitCode = 1;
}

main();
