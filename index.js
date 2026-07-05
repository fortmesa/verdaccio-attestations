'use strict';

// Pinned to 1.x deliberately -- DO NOT bump to 2.x. Verdaccio's own core
// publish handler still bundles body-parser@1.20.5 internally, and 1.x/2.x
// don't safely chain: 1.x's read() flags an already-consumed request via an
// explicit req._body flag set synchronously; 2.x instead checks
// onFinished.isFinished(req), an async/event-based signal that can still
// read false immediately after a *different* body-parser instance already
// fully drained the stream. Confirmed by direct repro (chaining this
// plugin's own bodyParser.json() ahead of Verdaccio's bundled 1.x instance
// on one real request): 1-then-1 and 2-then-2 both work, but 2-then-1 fails
// every time with "stream is not readable" -- silently breaking every
// publish once this middleware's own parser has already run. Only safe to
// upgrade this once Verdaccio's own bundled body-parser also moves to 2.x.
const bodyParser = require('body-parser');
const semver = require('semver');
const {minimatch} = require('minimatch');
const nodeFetch = require('node-fetch');
const https = require('node:https');
const {HttpsProxyAgent} = require('https-proxy-agent');
const {verifyBundle, verifyAttestationsResponse} = require('./verify');

// Must match this package's name -- Verdaccio's plugin loader resolves a
// scoped package name verbatim as the config key, and both `filters:` and
// `middlewares:` need to agree on this key to share config (same pattern
// verdaccio-security-filter's PLUGIN_CONFIG_KEY already establishes).
const PLUGIN_CONFIG_KEY = '@fortmesa/verdaccio-attestations';

const ATTESTATIONS_PATH_PREFIX = '/-/npm/v1/attestations/';
const REAL_NPM_REGISTRY = 'https://registry.npmjs.org';

// Same matching convention Verdaccio's own packages: access-control config
// uses (@verdaccio/utils's getMatchedPackagesSpec: real minimatch globs,
// not a narrower custom pattern language) -- an operator configuring this
// plugin already knows this syntax from Verdaccio core itself.
function matchesPackageName(pattern, name) {
  return minimatch(name, pattern);
}
function matchesVersion(rule, version) {
  return (
    !rule.versions ||
    semver.satisfies(version, rule.versions, {includePrerelease: true})
  );
}
function findMatchingRules(rules, name, version) {
  return rules.filter(
    r => matchesPackageName(r.pattern, name) && matchesVersion(r, version),
  );
}

// Same bare-string-or-single-key-object shape verdaccio-security-filter's
// block:/allow: lists already use: a bare pattern matches every version of
// whatever it matches, or {pattern: {versions?, strategy?}} scopes it to a
// semver range and/or picks a per-rule remove/replace strategy. No global
// default strategy -- same as security-filter, each rule decides its own.
function normalizeRule(entry, source) {
  if (typeof entry === 'string') return {pattern: entry};
  if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
    const keys = Object.keys(entry);
    if (keys.length !== 1) {
      throw new Error(
        `verdaccio-attestations: ${source} rule must have exactly one pattern key: ${JSON.stringify(entry)}`,
      );
    }
    const [pattern] = keys;
    const details = entry[pattern] ?? {};
    if (typeof details !== 'object' || Array.isArray(details)) {
      throw new Error(
        `verdaccio-attestations: ${source} rule for '${pattern}' must map to an object with optional 'versions'/'strategy'`,
      );
    }
    return {pattern, versions: details.versions, strategy: details.strategy};
  }
  throw new Error(
    `verdaccio-attestations: ${source} rule must be a pattern string or {pattern: {versions?, strategy?}} object: ${JSON.stringify(entry)}`,
  );
}

function compileRules(rules, source) {
  return rules.map(entry => {
    const rule = normalizeRule(entry, source);
    if (rule.versions && !semver.validRange(rule.versions)) {
      throw new Error(
        `verdaccio-attestations: ${source} rule has invalid semver range '${rule.versions}': ${JSON.stringify(entry)}`,
      );
    }
    if (
      rule.strategy &&
      rule.strategy !== 'remove' &&
      rule.strategy !== 'replace'
    ) {
      throw new Error(
        `verdaccio-attestations: ${source} rule has invalid strategy '${rule.strategy}' (must be 'remove' or 'replace')`,
      );
    }
    return rule;
  });
}

// Splits "<name>@<version>" (name may itself start with "@" for a scoped
// package, e.g. "@actions/core@3.0.1") on the LAST "@" -- the only
// unambiguous split point, since the name's own leading "@" (if scoped) is
// never the last one.
function splitPkgAtVersion(pkgAtVersion) {
  const at = pkgAtVersion.lastIndexOf('@');
  if (at <= 0) return null; // no "@", or "@" is the first character (no version given)
  return {name: pkgAtVersion.slice(0, at), version: pkgAtVersion.slice(at + 1)};
}

// One base name per package@version, alongside the tarball in the same
// per-package storage location. Exactly one object is ever stored under
// it -- <base>.good or <base>.bad, never both, and never a separate
// .sigstore file -- see _readStoredVerdict()/_storeVerdictAndBundle() for
// why: the verdict lives in the extension itself, not a second object.
function attestationBaseFilename(name, version) {
  return `${name.replace('/', '-')}-${version}`;
}

// Nearest older non-blocked version, falling back to nearest newer, then
// null (caller hard-removes) if nothing is available -- same substitute
// algorithm verdaccio-security-filter's strategy:'replace' already uses.
function pickReplacementSubstitute(ver, available) {
  const older = available.filter(v => semver.lt(v, ver));
  if (older.length > 0) return older[older.length - 1];
  const newer = available.filter(v => semver.gt(v, ver));
  if (newer.length > 0) return newer[0];
  return null;
}

class Attestations {
  constructor(config, options) {
    this.logger = options.logger;

    // Shared config lookup: filters: and middlewares: are two independent
    // plugin instances (Verdaccio's loader instantiates each config-section
    // entry separately) -- read from the canonical filters: section so both
    // agree on one rule set, same pattern verdaccio-security-filter uses.
    const sharedConfig = options.config?.filters?.[PLUGIN_CONFIG_KEY] ?? config;

    this.blockRules = compileRules(sharedConfig.block ?? [], 'block');
    this.allowRules = compileRules(sharedConfig.allow ?? [], 'allow');
    this.sigstoreOptions = sharedConfig.sigstore ?? {};
    this.strictSsl =
      sharedConfig.strict_ssl !== undefined ? sharedConfig.strict_ssl : true;

    // Default false: this plugin never talks to the real npm registry
    // unless explicitly opted into. verdaccio-offline-enforcer's
    // online/offline policy governs Verdaccio's own uplink fetches, but has
    // no visibility into this plugin's own direct HTTP calls -- defaulting
    // to "never fetch" is the only way this plugin can't quietly bypass
    // whatever policy governs a given deployment's traffic. When false, a
    // proxied package with no locally-stored verdict is simply treated as
    // unverifiable (blocked, if a block: rule covers it) rather than
    // reaching out.
    this.fetchUpstream = sharedConfig.fetchUpstream ?? false;

    // "name@version" -> {verified, reason, predicateType}. Populated once
    // per pod lifetime -- backed by _readStoredVerdict()'s persisted
    // .good/.bad object for anything that survives a restart.
    this._verdictCache = options.verdictCache ?? new Map();

    this._parseJsonBody = bodyParser.json({
      strict: false,
      limit: options.config?.max_body_size || '10mb',
    });

    // Test-only: inject a fake fetch so tests never make a real network call.
    this._fetch = options.fetch ?? nodeFetch;

    // "name@version" -> in-flight background verification Promise, for the
    // duration of that verification only (removed once it settles either
    // way). Never consulted by real request handling -- filter_metadata()
    // fires these and moves on -- but lets a test await
    // whenAllBackgroundWorkSettles() instead of guessing a timeout for
    // sigstore.verify()'s own (real, sometimes network-bound) work to finish.
    this._pendingBackground = new Map();
  }

  _trackBackground(key, promise) {
    const tracked = promise.finally(() => this._pendingBackground.delete(key));
    this._pendingBackground.set(key, tracked);
    return tracked;
  }

  // Test-only entry point: resolves once every background verification
  // in flight at the time of the call has settled (including any that
  // were themselves triggered by ones already in flight -- loops until the
  // set is actually empty, not just once).
  async whenAllBackgroundWorkSettles() {
    while (this._pendingBackground.size > 0) {
      await Promise.all([...this._pendingBackground.values()]);
    }
  }

  // Requires a verified SLSA provenance attestation for any version
  // matching a block: rule (unless it also matches an allow: rule). A
  // version with no attestation at all, or one that fails verification, is
  // blocked the same way -- "no proof" and "disproven" are treated
  // identically, both fail the requirement.
  //
  // Never awaits a live network fetch here, only the fast tier (packument-
  // embedded verdict, in-memory cache, or a single persisted-storage read)
  // -- a version with no answer at any of those is failed closed
  // immediately (consistent with "block: means require proof, no proof
  // yet available also means no"), while the real check (which may include
  // an upstream fetch, gated by fetchUpstream) runs in the background so a
  // later read sees the actual verdict without this request ever blocking
  // on it. This also means checking one version's status costs nothing
  // extra for any of the package's *other* versions -- each is resolved
  // independently, and all of them run concurrently, not one after another.
  async filter_metadata(packageInfo) {
    if (this.blockRules.length === 0) return packageInfo; // disabled

    const versions = packageInfo.versions ?? {};
    const versionEntries = Object.keys(versions);

    const gated = versionEntries.filter(ver => {
      if (findMatchingRules(this.allowRules, packageInfo.name, ver).length > 0)
        return false;
      return (
        findMatchingRules(this.blockRules, packageInfo.name, ver).length > 0
      );
    });
    if (gated.length === 0) return packageInfo;

    const verdicts = await Promise.all(
      gated.map(ver =>
        this._resolveVerdictFast(packageInfo.name, ver, versions[ver]),
      ),
    );

    const blocked = new Set();
    const replaceRequested = new Set();

    gated.forEach((ver, i) => {
      const fast = verdicts[i];
      if (fast === undefined) {
        // Never resolved yet -- fail closed now, resolve for real in the
        // background (may include an upstream fetch, if fetchUpstream
        // allows it) so a subsequent read is fast and correct. Tracked in
        // _pendingBackground so callers that need to know (tests, mainly --
        // real request handling never waits on this) can deterministically
        // await completion instead of guessing a timeout.
        this._trackBackground(
          `${packageInfo.name}@${ver}`,
          this._resolveVerdict(packageInfo.name, ver, versions[ver]),
        );
      }
      const result = fast ?? {verified: false, reason: 'not yet verified'};
      if (result.verified) return;

      blocked.add(ver);
      const matchedBlockRules = findMatchingRules(
        this.blockRules,
        packageInfo.name,
        ver,
      );
      const strategy = matchedBlockRules.every(r => r.strategy === 'replace')
        ? 'replace'
        : 'remove';
      if (strategy === 'replace') replaceRequested.add(ver);
      this.logger.warn(
        {pkg: packageInfo.name, ver, reason: result.reason},
        'verdaccio-attestations: blocked -- version has no verified attestation (@{reason})',
      );
    });

    if (blocked.size === 0) return packageInfo;

    const available = versionEntries
      .filter(v => !blocked.has(v))
      .sort((a, b) => semver.compare(a, b));
    const availableStable = available.filter(
      v => semver.prerelease(v) === null,
    );

    for (const ver of blocked) {
      if (replaceRequested.has(ver)) {
        const substitute = pickReplacementSubstitute(ver, available);
        if (substitute) {
          packageInfo.versions[ver] = {
            ...packageInfo.versions[substitute],
            version: ver,
          };
          this.logger.warn(
            {pkg: packageInfo.name, ver, substitutedWith: substitute},
            'verdaccio-attestations: blocked -- replaced with nearest attested version',
          );
          continue;
        }
        this.logger.warn(
          {pkg: packageInfo.name, ver},
          'verdaccio-attestations: blocked -- replace requested but no attested substitute available, removed instead',
        );
      }
      delete packageInfo.versions[ver];
      delete packageInfo.time?.[ver];
    }

    const distTags = packageInfo['dist-tags'] ?? {};
    for (const tag of Object.keys(distTags)) {
      if (distTags[tag] in packageInfo.versions) continue;
      const candidates =
        availableStable.length > 0 ? availableStable : available;
      if (candidates.length > 0) {
        distTags[tag] = candidates[candidates.length - 1];
      } else {
        delete distTags[tag];
      }
    }

    return packageInfo;
  }

  // Synchronous, zero-I/O check: an internally-published package's own
  // stored verdict (already sitting in the metadata handed in) or this
  // pod's in-memory cache. Returns undefined -- a real sentinel, not just
  // a falsy verified:false -- when neither has an answer, so callers can
  // tell "known unverified" apart from "never checked at all".
  _peekVerdict(name, version, versionMeta) {
    if (versionMeta.dist?.attestations?.verified !== undefined) {
      return {
        verified: versionMeta.dist.attestations.verified,
        reason: versionMeta.dist.attestations.reason,
      };
    }
    return this._verdictCache.get(`${name}@${version}`);
  }

  // Adds exactly one persisted-storage read on top of _peekVerdict() --
  // still no network. This is the tier filter_metadata() awaits inline:
  // cheap enough to pay on every metadata read (a single small object
  // read, no cryptographic verification), and it's what makes a verdict
  // computed before a pod restart still count as "already known" after
  // one, without ever redoing the real (network-capable) resolution.
  async _resolveVerdictFast(name, version, versionMeta) {
    const cached = this._peekVerdict(name, version, versionMeta);
    if (cached !== undefined) return cached;

    const stored = await this._readStoredVerdict(name, version);
    if (!stored) return undefined;
    const result = {verified: stored.verified, reason: stored.reason};
    this._verdictCache.set(`${name}@${version}`, result);
    return result;
  }

  // The full resolution, including (if fetchUpstream allows it) a live
  // upstream fetch and real cryptographic verification -- the only
  // expensive path in this plugin, and the only one ever run in the
  // background rather than awaited inline from filter_metadata().
  async _resolveVerdict(name, version, versionMeta) {
    const fast = await this._resolveVerdictFast(name, version, versionMeta);
    if (fast !== undefined) return fast;

    const key = `${name}@${version}`;
    const integrity = versionMeta.dist?.integrity;
    if (!integrity) {
      // Deliberately not persisted -- this reflects incomplete input (no
      // integrity to check against yet), not a real verification failure,
      // and a later call might have real data.
      const result = {
        verified: false,
        reason: 'no dist.integrity available to verify against',
      };
      this._verdictCache.set(key, result);
      return result;
    }

    if (!this.fetchUpstream) {
      // Also deliberately not persisted -- fetchUpstream might get turned
      // on later, and this shouldn't calcify into a permanent .bad record.
      const result = {
        verified: false,
        reason:
          'fetchUpstream is disabled -- cannot verify a proxied package without contacting the real registry',
      };
      this._verdictCache.set(key, result);
      return result;
    }

    const attestationsResponse = await this._fetchFromUpstream(name, version);
    const result = attestationsResponse
      ? await verifyAttestationsResponse(
          {name, version, integrity},
          attestationsResponse,
          this.sigstoreOptions,
        )
      : {
          verified: false,
          reason:
            'no attestation available (not published here, not found upstream)',
        };

    this._verdictCache.set(key, result);
    if (result.bundle) {
      this._storeVerdictAndBundle(name, version, result.bundle, result).catch(
        err =>
          this.logger.warn(
            {pkg: name, ver: version, err: err.message},
            'verdaccio-attestations: failed to persist verdict',
          ),
      );
    }
    return result;
  }

  // Exactly one stored object per package@version, not two -- the verdict
  // lives in the FILENAME's own extension (.good/.bad), not a separate
  // marker file. Object-storage backends (this repo's S3 usage included)
  // typically bill per object with a real minimum regardless of content
  // size, so a second tiny file per version would be a genuine cost at
  // this data's scale; this reuses the one artifact already being stored
  // anyway. Deliberately built only on the generic addTarball/getTarball
  // interface every storage backend (S3, filesystem, or otherwise)
  // implements -- no S3-specific object metadata/tags, so this works
  // identically regardless of which backend is configured.
  async _readStoredVerdict(name, version) {
    const base = attestationBaseFilename(name, version);
    try {
      const {bundle} = await this._readBundle(name, `${base}.good`);
      return {verified: true, bundle};
    } catch {
      // no .good object -- fall through and try .bad
    }
    try {
      const {bundle, reason} = await this._readBundle(name, `${base}.bad`);
      return {verified: false, bundle, reason};
    } catch {
      return null; // neither exists -- never resolved yet
    }
  }

  _storeVerdictAndBundle(name, version, bundle, result) {
    const base = attestationBaseFilename(name, version);
    const filename = `${base}.${result.verified ? 'good' : 'bad'}`;
    const content = result.verified
      ? {bundle}
      : {bundle, reason: result.reason};
    return this._storeBundle(name, filename, content);
  }

  // Mirrors verdaccio-audit's ProxyAudit exactly: a plain HTTPS agent by
  // default (with strict_ssl controlling certificate validation), replaced
  // by an HttpsProxyAgent when auth.config.https_proxy is set, so this
  // plugin behaves the same way in a firewalled/corporate deployment that
  // routes all outbound npmjs traffic through a specific proxy.
  _requestAgent() {
    if (this._auth?.config?.https_proxy) {
      return new HttpsProxyAgent(this._auth.config.https_proxy);
    }
    return new https.Agent({rejectUnauthorized: this.strictSsl});
  }

  async _fetchFromUpstream(name, version) {
    try {
      const res = await this._fetch(
        `${REAL_NPM_REGISTRY}${ATTESTATIONS_PATH_PREFIX}${encodeURIComponent(name)}@${version}`,
        {agent: this._requestAgent()},
      );
      if (!res.ok) return null;
      return await res.json();
    } catch (err) {
      this.logger.warn(
        {pkg: name, ver: version, err: err.message},
        'verdaccio-attestations: failed to fetch attestation from upstream',
      );
      return null;
    }
  }

  register_middlewares(app, auth, storage) {
    this._storage = storage;
    this._auth = auth;

    app.use((req, res, next) => {
      if (req.method !== 'PUT') return next();
      // This middleware runs before Verdaccio's own router (which is what
      // populates req.params.package) even mounts -- parse the name from
      // the path directly, same as verdaccio-security-filter's own
      // publish-time gate already has to.
      const segments = req.path
        .replace(/\/%40/, '/@')
        .split('/')
        .filter(Boolean);
      if (segments.length === 0 || segments.length > 2 || segments[1] === '-')
        return next();
      const packageName = decodeURIComponent(segments[0]);

      this._parseJsonBody(req, res, err => {
        if (err) return next(err);
        this._interceptPublish(req, res, packageName).finally(() => next());
      });
    });

    app.get(`${ATTESTATIONS_PATH_PREFIX}:pkgAtVersion`, (req, res) => {
      this._handleGetAttestations(req, res).catch(err => {
        this.logger.error(
          {err: err.message},
          'verdaccio-attestations: unexpected error serving attestations',
        );
        res.status(500).end();
      });
    });
  }

  // Strips a .sigstore attachment out of an incoming publish body (before
  // Verdaccio's own core handler ever sees it -- its hasDiffOneKey() check
  // hard-rejects any publish whose _attachments has more than one key,
  // which is exactly what a real `npm publish --provenance` sends: the
  // tarball plus a .sigstore bundle), verifies it, stores it via the same
  // generic per-package blob storage the tarball itself uses, and injects
  // dist.attestations into the version metadata in the same request body --
  // so Verdaccio's own addVersion() persists it with no separate hook.
  async _interceptPublish(req, res, packageName) {
    const body = req.body;
    if (!body?._attachments || !body?.versions) return; // not a real publish (e.g. deprecate/star)

    const sigstoreKey = Object.keys(body._attachments).find(k =>
      k.endsWith('.sigstore'),
    );
    if (!sigstoreKey) return; // no provenance attached -- nothing for this plugin to do

    const version = Object.keys(body.versions)[0];
    const versionMeta = body.versions[version];
    if (!packageName || !version || !versionMeta) return;

    let bundle;
    try {
      bundle = JSON.parse(
        Buffer.from(body._attachments[sigstoreKey].data, 'base64').toString(
          'utf8',
        ),
      );
    } catch (err) {
      this.logger.warn(
        {pkg: packageName, ver: version, err: err.message},
        'verdaccio-attestations: publish included an unparseable .sigstore attachment, ignoring it',
      );
      delete body._attachments[sigstoreKey];
      return;
    }

    const integrity = versionMeta.dist?.integrity;
    const result = integrity
      ? await verifyBundle(
          {name: packageName, version, integrity},
          bundle,
          this.sigstoreOptions,
        )
      : {
          verified: false,
          reason: 'no dist.integrity on published version metadata',
        };

    // Deferred to the response's own 'finish' event, not stored inline here:
    // for a brand-new package's very first publish, the package has no
    // record in storage yet at this point -- this middleware runs before
    // Verdaccio's own core publish handler (reached only via next(), below)
    // has actually created it, and storage.addTarball() requires that
    // record to already exist (confirmed against verdaccio's own
    // local-storage.js: it 404s with "no such package available"
    // otherwise). Waiting for 'finish' guarantees Verdaccio has already
    // committed the package by the time this runs -- true for a
    // pre-existing package's publish too, so this is never later than
    // necessary. Checking res.statusCode also means a publish some other
    // downstream check (e.g. security-filter's own gate) ends up rejecting
    // never gets an orphaned verdict object stored for a version that was
    // never actually published.
    res.on('finish', () => {
      if (res.statusCode >= 300) return;
      // One stored object, named by verdict -- not stored separately from
      // the packument's own dist.attestations below, but kept independent
      // of it too: discoverable directly from storage (e.g. for tooling or
      // a rebuild) and reuses the exact same lookup path proxied packages
      // rely on via _readStoredVerdict(). Tracked via _trackBackground, the
      // same mechanism the background verdict-resolution path already uses,
      // so a caller (tests, mainly) can deterministically await it via
      // whenAllBackgroundWorkSettles() instead of racing the 'finish' event
      // against this fire-and-forget write actually completing.
      this._trackBackground(
        `publish:${packageName}@${version}`,
        this._storeVerdictAndBundle(packageName, version, bundle, result).catch(
          err =>
            this.logger.error(
              {pkg: packageName, ver: version, err: err.message},
              'verdaccio-attestations: failed to store attestation bundle/verdict',
            ),
        ),
      );
    });
    this._verdictCache.set(`${packageName}@${version}`, result);

    versionMeta.dist = versionMeta.dist ?? {};
    versionMeta.dist.attestations = {
      url: `${ATTESTATIONS_PATH_PREFIX}${encodeURIComponent(packageName)}@${version}`,
      verified: result.verified,
      reason: result.reason,
      predicateType: result.predicateType,
    };

    delete body._attachments[sigstoreKey];

    this.logger[result.verified ? 'info' : 'warn'](
      {
        pkg: packageName,
        ver: version,
        verified: result.verified,
        reason: result.reason,
      },
      result.verified
        ? 'verdaccio-attestations: publish attestation verified for @{pkg}@@{ver}'
        : 'verdaccio-attestations: publish attestation FAILED verification for @{pkg}@@{ver} (@{reason})',
    );
  }

  _storeRaw(packageName, filename, buffer) {
    return new Promise((resolve, reject) => {
      const stream = this._storage.addTarball(packageName, filename);
      stream.on('error', reject);
      stream.on('success', resolve);
      stream.end(buffer);
      stream.done();
    });
  }

  _readRaw(packageName, filename) {
    return new Promise((resolve, reject) => {
      const stream = this._storage.getTarball(packageName, filename);
      const chunks = [];
      stream.on('error', reject);
      stream.on('data', c => chunks.push(c));
      stream.on('end', () => resolve(Buffer.concat(chunks)));
    });
  }

  _storeBundle(packageName, filename, bundle) {
    return this._storeRaw(
      packageName,
      filename,
      Buffer.from(JSON.stringify(bundle)),
    );
  }

  async _readBundle(packageName, filename) {
    return JSON.parse(
      (await this._readRaw(packageName, filename)).toString('utf8'),
    );
  }

  // Serves an attestation bundle for direct client requests (the follow-up
  // GET a real npm/yarn client issues after seeing dist.attestations.url in
  // a packument -- see pacote's own re-resolve-to-configured-registry
  // behavior, which is why this always lands here rather than on the
  // literal upstream host). Prefers whatever's already stored (from a local
  // publish, or a verdict _resolveVerdict() already computed and cached) --
  // in the ordinary case, filter_metadata() already ran on the packument
  // fetch that surfaced this URL to the client in the first place, so this
  // is usually a hit. On a genuine miss (e.g. no block: rule covers this
  // package, so nothing ever triggered verification), this relays the raw
  // upstream response (if fetchUpstream allows it) without caching it --
  // caching a verdict here would need the package's dist.integrity to
  // verify against, which a bare attestations request doesn't carry.
  async _handleGetAttestations(req, res) {
    const parsed = splitPkgAtVersion(
      decodeURIComponent(req.params.pkgAtVersion),
    );
    if (!parsed) return res.status(400).end();
    const {name, version} = parsed;

    const stored = await this._readStoredVerdict(name, version);
    if (stored?.bundle)
      return res.status(200).json({attestations: [{bundle: stored.bundle}]});

    if (!this.fetchUpstream) return res.status(404).end();
    const fetched = await this._fetchFromUpstream(name, version);
    if (!fetched) return res.status(404).end();
    return res.status(200).json(fetched);
  }
}

module.exports = (config, options) => new Attestations(config, options);
module.exports.Attestations = Attestations;
