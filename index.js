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
const {AsyncLocalStorage} = require('node:async_hooks');
const {HttpsProxyAgent} = require('https-proxy-agent');
const {verifyBundle, verifyAttestationsResponse} = require('./verify');

// Must match this package's name -- Verdaccio's plugin loader resolves a
// scoped package name verbatim as the config key, and both `filters:` and
// `middlewares:` need to agree on this key to share config (same pattern
// verdaccio-security-filter's PLUGIN_CONFIG_KEY already establishes).
const PLUGIN_CONFIG_KEY = '@fortmesa/verdaccio-attestations';

// Sibling plugin whose online/offline policy this plugin's fetchUpstream
// gating must respect -- see the constructor and _isOfflineRestricted()
// below. Deliberately read directly by config key rather than through any
// runtime signal from that plugin (see the AsyncLocalStorage comment below
// for why a request-time signal doesn't work here); the two plugins are
// maintained together, so a config-shape change on one side implies
// touching this one too.
const OFFLINE_ENFORCER_CONFIG_KEY = '@fortmesa/verdaccio-offline-enforcer';

const ATTESTATIONS_PATH_PREFIX = '/-/npm/v1/attestations/';
// Only a fallback for a package with no proxy: configured at all -- see
// _resolveUpstreamRegistryUrls() below for why this isn't used
// unconditionally. Matches @verdaccio/config's own DEFAULT_REGISTRY
// constant (confirmed against its source) -- the same default Verdaccio
// itself falls back to, not a value invented here.
const DEFAULT_UPSTREAM_REGISTRY = 'https://registry.npmjs.org';
// filter_metadata() now awaits _resolveVerdict() directly for a
// never-before-seen version instead of backgrounding it (see that
// method's own comment on why) -- this bounds the one network call that
// can add to a metadata read's latency, so a slow/unresponsive upstream
// can't turn into a hung install instead of a (still fast) block.
const UPSTREAM_FETCH_TIMEOUT_MS = 5000;

// Carries the current request's offline-restriction decision from
// register_middlewares() (real req access) down into filter_metadata() and
// _handleGetAttestations() (neither has req access -- filter_metadata's
// signature is fixed by Verdaccio's own plugin-utils.d.ts as
// (manifest) => Promise<manifest>, no request context at all). Confirmed
// empirically against a real running Verdaccio process, including under
// concurrent requests, that a context set here survives Verdaccio's entire
// internal getPackage() -> _syncUplinksMetadata() -> _applyFilters() call
// chain with correct per-request isolation (no cross-request leakage).
// Module-level like sharedStorage/sharedAuth below -- not tied to either
// plugin-instance role, so it works the same regardless of which instance
// (filter or middleware) ends up running a given piece of code.
const requestContext = new AsyncLocalStorage();

// Bridges register_middlewares()'s storage/auth handles across to the
// SEPARATE filter-role instance (see the constructor comment on
// PLUGIN_CONFIG_KEY lookup below) -- both instances live in the same
// process/module, so a module-level slot is the only thing they share.
// Without this, any verdict resolved via filter_metadata()'s background
// path (real fetchUpstream verification, not a same-request local publish)
// crashes trying to persist on an instance that never received storage --
// caught and logged, but silently defeating the entire point of persisting
// a verdict at all: every such package re-verifies from scratch on every
// process/replica that hasn't itself already resolved it in memory.
// Assumes one Verdaccio process hosts one logical configuration of this
// plugin, same assumption the shared filters:-config lookup already makes.
let sharedStorage;
let sharedAuth;

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

// Fail loud at startup on a malformed entry, not silently-matches-nothing
// (or matches-everything) at publish time -- same principle compileRules()
// above already applies to block:/allow:. Not GitHub-specific: each entry
// is {issuer?, subjectAlternativeName?} (see verify.js's
// matchesTrustedPublisher() for how these are checked against a verified
// certificate's own identity), so any Sigstore-compatible OIDC issuer's
// shape can be configured, not just GitHub Actions'.
function compileTrustedPublishers(entries) {
  return entries.map(entry => {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      throw new Error(
        `verdaccio-attestations: sigstore.trustedPublishers entry must be an object with 'issuer' and/or 'subjectAlternativeName': ${JSON.stringify(entry)}`,
      );
    }
    const {issuer, subjectAlternativeName, ...rest} = entry;
    if (Object.keys(rest).length > 0) {
      throw new Error(
        `verdaccio-attestations: sigstore.trustedPublishers entry has unknown key(s) ${Object.keys(rest).join(', ')}: ${JSON.stringify(entry)}`,
      );
    }
    if (issuer === undefined && subjectAlternativeName === undefined) {
      throw new Error(
        `verdaccio-attestations: sigstore.trustedPublishers entry must set at least one of 'issuer'/'subjectAlternativeName': ${JSON.stringify(entry)}`,
      );
    }
    if (issuer !== undefined && typeof issuer !== 'string') {
      throw new Error(
        `verdaccio-attestations: sigstore.trustedPublishers entry's 'issuer' must be a string: ${JSON.stringify(entry)}`,
      );
    }
    if (
      subjectAlternativeName !== undefined &&
      typeof subjectAlternativeName !== 'string'
    ) {
      throw new Error(
        `verdaccio-attestations: sigstore.trustedPublishers entry's 'subjectAlternativeName' must be a string: ${JSON.stringify(entry)}`,
      );
    }
    return {issuer, subjectAlternativeName};
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

// Rejects anything that could let name/version escape a single logical
// storage key/path segment once handed to attestationFilename() below --
// checked here, in this plugin's own code, rather than trusted to whatever
// storage backend (filesystem, S3, ...) happens to be configured
// underneath: backends differ in whether/how they sanitize a key derived
// from these values (the bundled filesystem backend happens to strip a
// bare ".."/"." path segment itself, but that's that backend's own
// behavior, not a contract this plugin can rely on for every backend it
// might be paired with).
function isSafePathSegment(value) {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 214 &&
    !/[\x00-\x1f]/.test(value) &&
    !/(^|\/)\.\.($|\/)/.test(value)
  );
}

// A package name may contain exactly one "/" (the scope separator, e.g.
// "@scope/pkg") -- never zero-or-two-plus in any other shape, and never a
// bare ".."/"." segment on either side of it.
function isSafePackageName(name) {
  if (!isSafePathSegment(name)) return false;
  const segments = name.split('/');
  if (segments.length > 2) return false;
  if (segments.length === 2 && !segments[0].startsWith('@')) return false;
  return true;
}

// A version string never legitimately contains a "/" at all.
function isSafeVersion(version) {
  return isSafePathSegment(version) && !version.includes('/');
}

// One file per package@version, alongside the tarball in the same
// per-package storage location -- never a separate .sigstore file, see
// _readStoredVerdict()/_storeVerdictAndBundle() for why: the verdict and
// its bundle live in one object's contents ({verified, bundle, reason}),
// not encoded in the filename. A single lookup either hits or misses --
// no second attempt needed to tell "known bad" apart from "never checked".
function attestationFilename(name, version) {
  return `${name.replace(/\//g, '-')}-${version}.attestation`;
}

// Given a real tarball's own filename (e.g. "core-3.0.1.tgz" for
// "@actions/core" -- real npm strips the scope from the tarball name,
// confirmed against a real registry.npmjs.org response) and the ALREADY-
// KNOWN package name it belongs to, recovers the version. Unambiguous
// specifically because the package name is already known, not guessed --
// this only strips a known prefix/suffix, it never tries to split an
// arbitrary "name-version" string on its own.
function deriveVersionFromTarballFilename(packageName, filename) {
  const unscopedName = packageName.includes('/')
    ? packageName.slice(packageName.indexOf('/') + 1)
    : packageName;
  const prefix = `${unscopedName}-`;
  if (!filename.startsWith(prefix) || !filename.endsWith('.tgz')) return null;
  return filename.slice(prefix.length, -'.tgz'.length);
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

    // Only ever applied to a LOCAL publish's own .sigstore attachment (see
    // _interceptPublish() below) -- never to a proxied, third-party
    // package's upstream-fetched attestation (_resolveVerdict() never
    // passes this to verifyBundle()/verifyAttestationsResponse(); see
    // docs/configuration.md's "Verification" section for why that
    // distinction matters). Absent/empty means no identity check at all --
    // the same permissive-by-default posture block:/allow: already have --
    // not a hard requirement, since this is new, opt-in hardening on top of
    // existing behavior.
    this.trustedPublishers = compileTrustedPublishers(
      this.sigstoreOptions.trustedPublishers ?? [],
    );

    // Default false: this plugin never talks to the real npm registry
    // unless explicitly opted into. When false, a proxied package with no
    // locally-stored verdict is simply treated as unverifiable (blocked, if
    // a block: rule covers it) rather than reaching out. This is the
    // static, whole-deployment default -- see _isOfflineRestricted() below
    // for the additional PER-REQUEST override that can force this off for
    // one specific identity even when the static config says true.
    this.fetchUpstream = sharedConfig.fetchUpstream ?? false;

    // verdaccio-offline-enforcer's own online/offline policy, read
    // directly from its config section rather than from any runtime signal
    // it produces -- see the requestContext/AsyncLocalStorage comment
    // above for why a request-time signal from that plugin doesn't work
    // (its own gating can swallow a request via its internal
    // storage.getPackage() call without ever reaching a shared middleware
    // ordering point both plugins could rely on). Mirrors
    // OfflineEnforcer's own _isRestricted() field-for-field, including its
    // exact defaults -- these two plugins are maintained together, so a
    // rename on that side (already happened once: onlineUsernames/
    // offlineUsernames -> online/offline) is expected to come with an
    // update here too, not defended against.
    const offlineEnforcerConfig =
      options.config?.middlewares?.[OFFLINE_ENFORCER_CONFIG_KEY];
    this._offlineOnline = new Set(offlineEnforcerConfig?.online ?? []);
    this._offlineOffline = new Set(offlineEnforcerConfig?.offline ?? []);
    this._offlineEnforceForAnonymous =
      offlineEnforcerConfig?.enforceForAnonymous ?? true;
    this._offlineEnforceForUnknown =
      offlineEnforcerConfig?.enforceForUnknown ?? false;

    // "name@version" -> {verified, reason, predicateType}. Populated once
    // per pod lifetime -- backed by _readStoredVerdict()'s persisted
    // object for anything that survives a restart.
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
  // Awaits the real resolution (_resolveVerdict(), which may include a
  // bounded-timeout upstream fetch -- see UPSTREAM_FETCH_TIMEOUT_MS on
  // _fetchFromUpstream() below) for any version the fast tier (packument-
  // embedded verdict, in-memory cache, or a single persisted-storage read)
  // doesn't already have an answer for. This used to fail closed
  // immediately on a never-before-seen version and resolve it in the
  // background instead -- deliberately changed: the very first read of any
  // given version was *guaranteed* wrong (blocked, even for a package that
  // would have verified cleanly) purely because nothing had checked it yet,
  // which is a real, confusing false negative for whichever client happens
  // to be first, not just a one-time cold-cache cost. Every gated version
  // still resolves independently and concurrently (Promise.all below, same
  // as before) -- checking one version's status still costs nothing extra
  // for any of the package's *other* versions, only now the whole call
  // waits for the slowest one to finish instead of returning early.
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

    const fastResults = await Promise.all(
      gated.map(ver =>
        this._resolveVerdictFast(packageInfo.name, ver, versions[ver]),
      ),
    );
    const verdicts = await Promise.all(
      gated.map((ver, i) =>
        fastResults[i] !== undefined
          ? fastResults[i]
          : this._resolveVerdict(packageInfo.name, ver, versions[ver]),
      ),
    );

    const blocked = new Set();
    const replaceRequested = new Set();

    gated.forEach((ver, i) => {
      const result = verdicts[i];
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

    if (!this._effectiveFetchUpstream()) {
      // Also deliberately not persisted -- this may only reflect this one
      // request's identity being offline-restricted, or fetchUpstream might
      // get turned on later either way -- this shouldn't calcify into a
      // permanent bad record.
      const result = {
        verified: false,
        reason:
          'fetchUpstream is disabled (or this request is offline-restricted) -- cannot verify a proxied package without contacting the real registry',
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

  // Exactly one stored object per package@version -- the verdict is a field
  // in the object's own contents, not encoded in the filename. One lookup
  // either hits or misses; no second attempt needed to tell "known bad"
  // apart from "never checked". Deliberately built only on the generic
  // addTarball/getTarball interface every storage backend (S3, filesystem,
  // or otherwise) implements via storage.localStorage -- no S3-specific
  // object metadata/tags, so this works identically regardless of which
  // backend is configured, and null when no persistent storage is reachable
  // at all (see _getLocalStorage()) is treated the same as "never checked".
  async _readStoredVerdict(name, version) {
    if (!this._getLocalStorage()) return null;
    try {
      const {verified, bundle, reason} = await this._readBundle(
        name,
        attestationFilename(name, version),
      );
      return {verified, bundle, reason};
    } catch {
      return null; // no object yet, or no persistent storage -- never resolved
    }
  }

  _storeVerdictAndBundle(name, version, bundle, result) {
    if (!this._getLocalStorage()) return Promise.resolve(); // in-memory-only fallback -- nothing to persist to
    const content = result.verified
      ? {verified: true, bundle}
      : {verified: false, bundle, reason: result.reason};
    return this._storeBundle(name, attestationFilename(name, version), content);
  }

  // Falls back to the module-level shared handle when this instance is the
  // filter-role one (never received its own via register_middlewares) --
  // see the comment on sharedStorage/sharedAuth above.
  _getAuth() {
    return this._auth ?? sharedAuth;
  }

  // The `storage` register_middlewares() receives is Verdaccio core's
  // top-level orchestrating Storage class -- ITS OWN addTarball/getTarball
  // must never be used for verdict persistence: getTarball(), on any miss,
  // automatically falls back to "sync metadata from the uplink", which
  // re-invokes every registered filter's filter_metadata() (ours included)
  // -- and _readStoredVerdict()'s very first check for a never-before-seen
  // package@version is *guaranteed* to miss, so this recurses into itself
  // forever. Confirmed by hanging a real Verdaccio process this way, for a
  // purely local package with zero uplinks configured too -- not proxy-
  // specific, this is inherent to calling Storage.getTarball() from inside
  // filter_metadata() at all.
  //
  // storage.localStorage is a different, lower-level class (local-storage.js)
  // that Storage wraps -- a plain, non-private property (confirmed:
  // `this.localStorage = ...` in Storage's own constructor), whose own
  // addTarball/getTarball/removeTarball are thin wrappers directly over the
  // configured storage plugin (filesystem or S3) with no uplink fallback
  // and no filter re-check at all. Present under that exact name since
  // Verdaccio 2.3.0 (2017), unchanged through the 3.0 TypeScript rewrite
  // and the 5->6 jump -- stable, though not part of Verdaccio's documented
  // plugin API, so this could in principle move in some future major
  // version.
  //
  // Returns null (not undefined) when no persistent storage is reachable
  // at all -- this instance never received one via register_middlewares
  // AND no other instance in this process has either, or the one that did
  // has no .localStorage yet -- callers treat that as "go in-memory-only",
  // not as an error.
  _getLocalStorage() {
    const storage = this._storage ?? sharedStorage;
    return storage?.localStorage ?? null;
  }

  // Mirrors OfflineEnforcer's own _isRestricted() field-for-field (see the
  // constructor comment on _offlineOnline/_offlineOffline for why this is
  // duplicated code reading shared config values, not a shared function) --
  // online wins over offline if both somehow match, then enforceForUnknown
  // decides anyone matching neither. real_groups specifically (not
  // .groups): Verdaccio's createRemoteUser() puts a user's plugin-provided
  // groups there, distinct from the universal $all/$authenticated-style
  // defaults every logged-in user also gets, which would make every
  // authenticated user match some default group otherwise.
  _isOfflineRestricted(remoteUser) {
    if (remoteUser?.name === undefined) return this._offlineEnforceForAnonymous;
    const identities = [remoteUser.name, ...(remoteUser.real_groups ?? [])];
    if (identities.some(id => this._offlineOnline.has(id))) return false;
    if (identities.some(id => this._offlineOffline.has(id))) return true;
    return this._offlineEnforceForUnknown;
  }

  // The actual per-request answer to "is a live upstream fetch allowed
  // right now" -- the static fetchUpstream config AND this specific
  // request's identity not being offline-restricted. Fails closed (no
  // fetch) when there's no request context at all -- reachable only from
  // non-HTTP code paths (e.g. Verdaccio's own web-UI package listing),
  // where there's no identity to evaluate in the first place.
  _effectiveFetchUpstream() {
    if (!this.fetchUpstream) return false;
    const ctx = requestContext.getStore();
    if (!ctx) return false;
    return !ctx.offlineRestricted;
  }

  // Mirrors verdaccio-audit's ProxyAudit exactly: a plain HTTPS agent by
  // default (with strict_ssl controlling certificate validation), replaced
  // by an HttpsProxyAgent when auth.config.https_proxy is set, so this
  // plugin behaves the same way in a firewalled/corporate deployment that
  // routes all outbound npmjs traffic through a specific proxy.
  _requestAgent() {
    const auth = this._getAuth();
    if (auth?.config?.https_proxy) {
      return new HttpsProxyAgent(auth.config.https_proxy);
    }
    return new https.Agent({rejectUnauthorized: this.strictSsl});
  }

  // Verdaccio's own config -- not a hardcoded assumption -- decides where a
  // given package's content actually comes from: getMatchedPackagesSpec(name)
  // (confirmed against @verdaccio/config's own source, the same method
  // @verdaccio/local-storage-legacy's getPackageStorage() already uses for
  // per-package storage routing) returns that package's own `proxy` list --
  // the uplink name(s) its packages: pattern is configured to use -- and
  // config.uplinks[name].url resolves each to an actual URL. A deployment
  // proxying from somewhere other than the real npm registry (an internal
  // mirror, Artifactory, an air-gapped replica) must have its attestations
  // fetched from THAT source, not always the public internet regardless of
  // what's actually configured -- querying the wrong registry could mean
  // silently checking attestations for a different build of the package
  // than the one this instance is actually serving, and unconditionally
  // reaching out to the public npm registry defeats the entire point of an
  // otherwise fully air-gapped uplink. Falls back to DEFAULT_UPSTREAM_REGISTRY
  // only when a package genuinely has no proxy configured at all -- the
  // same fallback Verdaccio's own DEFAULT_REGISTRY/DEFAULT_UPLINK constants
  // already default to, not a value this plugin invents on its own.
  _resolveUpstreamRegistryUrls(name) {
    const config = this._getAuth()?.config;
    const matched = config?.getMatchedPackagesSpec?.(name);
    const proxyNames = matched?.proxy ? [].concat(matched.proxy) : [];
    const urls = proxyNames
      .map(uplinkName => config?.uplinks?.[uplinkName]?.url)
      .filter(Boolean);
    return urls.length > 0 ? urls : [DEFAULT_UPSTREAM_REGISTRY];
  }

  async _fetchFromUpstream(name, version) {
    for (const registryUrl of this._resolveUpstreamRegistryUrls(name)) {
      try {
        const res = await this._fetch(
          `${registryUrl.replace(/\/$/, '')}${ATTESTATIONS_PATH_PREFIX}${encodeURIComponent(name)}@${version}`,
          {
            agent: this._requestAgent(),
            // filter_metadata() now awaits this call directly (see its own
            // comment on why) rather than backgrounding it -- an unbounded
            // fetch here would turn a slow/unresponsive upstream into a
            // hung metadata read instead of the wrong-but-fast answer this
            // used to give. A timeout (same treatment as any other fetch
            // failure: logged, treated as "no attestation", never thrown
            // past this method) bounds that without needing new config.
            signal: AbortSignal.timeout(UPSTREAM_FETCH_TIMEOUT_MS),
          },
        );
        if (res.ok) return await res.json();
      } catch (err) {
        this.logger.warn(
          {pkg: name, ver: version, registryUrl, err: err.message},
          'verdaccio-attestations: failed to fetch attestation from upstream',
        );
      }
    }
    return null;
  }

  register_middlewares(app, auth, storage) {
    this._storage = storage;
    this._auth = auth;
    sharedStorage = storage;
    sharedAuth = auth;

    // Unconditional and first: establishes this request's offline-
    // restriction context before anything else in this plugin (or
    // Verdaccio's own downstream handling, which is what eventually calls
    // filter_metadata()) runs. See the requestContext/AsyncLocalStorage
    // comment above -- this is what makes that context visible from
    // filter_metadata() and _handleGetAttestations() further down the
    // chain, verified empirically to survive Verdaccio's internal
    // getPackage() -> _syncUplinksMetadata() -> _applyFilters() chain.
    app.use((req, res, next) => {
      requestContext.run(
        {offlineRestricted: this._isOfflineRestricted(req.remote_user)},
        () => next(),
      );
    });

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

    // Mirrors the real tarball's own lifecycle -- Verdaccio's dedicated
    // single-tarball delete route (DELETE /:package/-/:filename/-rev/:revision,
    // -> storage.removeTarball()) is the one real gap in "this plugin's own
    // stored verdict tracks its tarball's lifecycle": full package removal
    // already cleans up every _attachments entry (ours included) via
    // Verdaccio's own removePackage(), for free, but nothing previously
    // caught a single tarball being deleted this way. Deliberately does NOT
    // add cleanup for single-version unpublish (PUT with fewer versions,
    // Verdaccio's own changePackage()) -- that path doesn't delete the real
    // tarball either, only clears a bookkeeping field, and this plugin's
    // stated principle is to match Verdaccio's own tarball lifecycle, not
    // exceed it.
    app.use((req, res, next) => {
      if (req.method !== 'DELETE') return next();
      const segments = req.path
        .replace(/\/%40/, '/@')
        .split('/')
        .filter(Boolean);
      if (
        segments.length !== 5 ||
        segments[1] !== '-' ||
        segments[3] !== '-rev'
      )
        return next();
      const packageName = decodeURIComponent(segments[0]);
      const filename = decodeURIComponent(segments[2]);
      const version = deriveVersionFromTarballFilename(packageName, filename);
      if (!version) return next();

      // Best-effort, deferred until the real delete actually succeeds --
      // same res.on('finish')/statusCode guard _interceptPublish already
      // uses, so a rejected delete (e.g. permission denied) never triggers
      // cleanup for a tarball that's still actually there.
      res.on('finish', () => {
        if (res.statusCode >= 300) return;
        const localStorage = this._getLocalStorage();
        if (!localStorage) return;
        localStorage.removeTarball(
          packageName,
          attestationFilename(packageName, version),
          undefined, // revision -- Verdaccio's own removeTarball never reads this param either
          err => {
            // A 404 here just means this version was never verified (no
            // stored verdict to clean up) -- not a real failure. Checking
            // the numeric status (Verdaccio's own getNotFound() sets
            // err.code to the HTTP status, not a string like 'ENOENT')
            // rather than matching its message text, which isn't a stable
            // contract across Verdaccio versions.
            if (err && err.code !== 404) {
              this.logger.warn(
                {pkg: packageName, ver: version, err: err.message},
                'verdaccio-attestations: failed to remove stored verdict for a deleted tarball',
              );
            }
          },
        );
      });
      next();
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
          // Empty (the default, unconfigured) means no identity check --
          // verifyBundle() treats a truthy-but-empty array as "matches
          // nothing", so this must be null, not [], to mean "not enforced".
          this.trustedPublishers.length > 0 ? this.trustedPublishers : null,
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
      // MUST be absolute -- confirmed directly against real npmjs.org's own
      // packument (dist.attestations.url is a full https://registry.npmjs.org/...
      // URL, never a bare path) and against a real crash this caused: a
      // relative path here makes `npm audit signatures` (npm 10+, which also
      // verifies provenance attestations, not just registry signatures)
      // throw `TypeError: Invalid URL` inside pacote's RegistryFetcher --
      // it constructs `new URL(dist.attestations.url)` with no base, which
      // only works for an absolute URL. req.protocol/req.get('host') reflect
      // what the client actually connected to (respecting Verdaccio's own
      // server.trustProxy setting behind a proxy/ALB), matching how
      // Verdaccio's own dist.tarball URLs are already built.
      url: `${req.protocol}://${req.get('host')}${ATTESTATIONS_PATH_PREFIX}${encodeURIComponent(packageName)}@${version}`,
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
    const localStorage = this._getLocalStorage();
    if (!localStorage)
      return Promise.reject(new Error('no persistent storage available'));
    return new Promise((resolve, reject) => {
      const stream = localStorage.addTarball(packageName, filename);
      stream.on('error', reject);
      stream.on('success', resolve);
      stream.end(buffer);
      stream.done();
    });
  }

  _readRaw(packageName, filename) {
    const localStorage = this._getLocalStorage();
    if (!localStorage)
      return Promise.reject(new Error('no persistent storage available'));
    return new Promise((resolve, reject) => {
      const stream = localStorage.getTarball(packageName, filename);
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
    // req.params.pkgAtVersion is already percent-decoded once by Express's
    // own router (confirmed against the installed express/router package --
    // layer.js's decode_param() runs decodeURIComponent on every captured
    // param before it ever reaches a route handler). Decoding it again here
    // would let a double-percent-encoded value (e.g.
    // "%2540scope%252Fpkg%25401.0.0") smuggle a literal "/" or ".." past
    // Express's own single decode pass, straight into name/version below.
    // isSafePackageName()/isSafeVersion() are the real defense (they hold
    // regardless of what a second decode could produce), but not decoding
    // twice in the first place removes the easiest way to reach them with a
    // surprising value.
    const parsed = splitPkgAtVersion(req.params.pkgAtVersion);
    if (
      !parsed ||
      !isSafePackageName(parsed.name) ||
      !isSafeVersion(parsed.version)
    ) {
      return res.status(400).end();
    }
    const {name, version} = parsed;

    const stored = await this._readStoredVerdict(name, version);
    if (stored?.bundle)
      return res.status(200).json({attestations: [{bundle: stored.bundle}]});

    if (!this._effectiveFetchUpstream()) return res.status(404).end();
    const fetched = await this._fetchFromUpstream(name, version);
    if (!fetched) return res.status(404).end();
    return res.status(200).json(fetched);
  }
}

module.exports = (config, options) => new Attestations(config, options);
module.exports.Attestations = Attestations;
// Test-only: lets a unit test simulate "a real request came in" (via
// requestContext.run({offlineRestricted}, fn)) around a direct method call
// that doesn't go through register_middlewares' own Express middleware --
// real request handling never imports this.
module.exports.requestContext = requestContext;
// Test-only: sharedStorage/sharedAuth are module-level (see the comment on
// their declaration) so they persist across every test in the same process
// -- a test that specifically wants to exercise "no persistent storage
// reachable at all" needs a way to guarantee that, not just hope no earlier
// test in the same run already called register_middlewares().
module.exports.__resetSharedStateForTests = () => {
  sharedStorage = undefined;
  sharedAuth = undefined;
};
