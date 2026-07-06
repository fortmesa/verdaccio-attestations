# Configuration reference

See the [README](../README.md) for the plugin's overall behavior and a
quick-start config. This page covers everything else in depth.

## Full config

```yaml
filters:
  '@fortmesa/verdaccio-attestations':
    fetchUpstream: false # default false -- see "fetchUpstream and live upstream calls" below
    strict_ssl: true # default true -- certificate validation for direct (non-proxied) upstream requests
    block: [] # optional enforcement list -- see "Matching: block/allow" below
    allow: [] # optional -- bypasses block entirely for a matching package/version
    sigstore: {} # optional -- passed through verbatim as sigstore.verify()'s options argument

middlewares:
  '@fortmesa/verdaccio-attestations': {} # required -- see "Why middlewares is not optional" below

  # Optional -- if configured (even alongside this plugin, not necessarily
  # actually enabled), this plugin's own fetchUpstream is additionally
  # gated per-request by this same online/offline policy -- see
  # "fetchUpstream and live upstream calls" below. Its absence just means
  # every request gets the static fetchUpstream value above, unconditionally.
  '@fortmesa/verdaccio-offline-enforcer':
    online: []
    offline: []
```

## Why `middlewares` is not optional

`verdaccio-security-filter`'s `middlewares:` role is opt-in (only needed for its
publish-time gate or OSV retroactive alert). This plugin's is not: publish
interception (accepting a `.sigstore` attachment) and the
`GET /-/npm/v1/attestations/:pkgAtVersion` route both need a `storage` reference
to read/write attestation bundles, and `register_middlewares()` is the only
Verdaccio plugin hook that ever receives one. So `middlewares:` must list this
plugin even if `block`/`allow` are both left empty and you only want the
storage/relay behavior -- an empty `{}` block is enough in that case, same as
`verdaccio-security-filter`'s own minimal `middlewares:` entry.

Both plugin instances read `block`/`allow`/`fetchUpstream`/`strict_ssl`/
`sigstore` from the canonical `filters: "@fortmesa/verdaccio-attestations":`
section regardless of which instance is evaluating them, so they never need to
be duplicated under `middlewares:` too -- and must use that exact, literal
scoped key: Verdaccio resolves a scoped plugin's config key verbatim, with no
`verdaccio-` prefix mangling, so a bare `attestations:` key here would never
match and this shared lookup would silently fall back to each instance's own
(much smaller) local config instead.

## Matching: block/allow

Enforcement is opt-in -- `filter_metadata()` is a no-op whenever `block` is
empty (the default), regardless of what `allow` contains. Each entry is either a
bare glob pattern string (matches every version of whatever it matches), or a
single-key `{pattern: {versions?, strategy?}}` object when a rule needs to be
scoped to a semver range or (for `block`) a `replace` strategy -- the identical
shape `verdaccio-security-filter`'s own `block:`/`allow:` lists use:

```yaml
filters:
  '@fortmesa/verdaccio-attestations':
    block:
      - '@your-scope/*'
      - some-pkg:
          versions: '>=2.0.0' # semver range, via the existing `semver` dependency
          strategy: replace # 'remove' (default) | 'replace'
    allow:
      - '@your-scope/known-unsigned-internal-tool'
      - colors:
          versions: '1.4.0'
```

**Pattern matching uses real `minimatch`** -- the same convention Verdaccio's
own `packages:` access-control config uses (via `@verdaccio/utils`'s
`getMatchedPackagesSpec`), not a narrower hand-rolled matcher: an exact string
like `"left-pad"` matches only that package; `"@your-scope/*"` matches anything
with that prefix, but (as a real minimatch `*`) never crosses a `/`, so it does
not match a package literally named `@your-scope` nor one nested an extra path
segment deep; `"**"` matches everything. An operator configuring this plugin
already knows this syntax from Verdaccio core itself.

**`versions`** (only available via the single-key object form) scopes a rule to
a semver range, checked with `includePrerelease: true`. A version outside every
matching rule's range (or outside a package's only rule's range) is never gated
at all -- not blocked, not required to have an attestation, simply untouched by
this plugin.

**`allow` overrides `block` entirely** for a matching package/version -- an
allow-listed version is never gated, checked, or blocked, full stop, same
precedence principle `verdaccio-security-filter`'s `allow:` list establishes.

**`strategy: replace`** (on a `block` rule) substitutes the nearest older
verified version (falling back to the nearest newer one, then to a hard removal
if neither exists) instead of removing the blocked version outright -- the same
substitute algorithm and rationale as `verdaccio-security-filter`'s own
`strategy: replace`. Multiple matching `block` rules only produce `replace` if
_every_ one of them says `replace`; otherwise the safer `remove` wins. The
packument keeps the blocked version's key and `version` field, but its `dist` is
copied wholesale from the substitute, so what actually gets installed for that
version number is the substitute's real, already-attested content.

After blocking, any `dist-tags` entry (e.g. `latest`) pointing at a version
actually removed is redirected to the newest remaining version (preferring a
stable, non-prerelease one); a tag is removed entirely if every remaining
version is also blocked.

## fetchUpstream and live upstream calls

Default **`false`**. This plugin never contacts `registry.npmjs.org` directly
unless explicitly opted into.

**With `fetchUpstream: false`** (default): a version with no locally-stored
attestation is treated as unverifiable -- blocked, if a `block` rule covers it
-- rather than reaching out. A bare `GET` to the attestations route for a
package with nothing stored locally 404s immediately, without attempting a
fetch.

**With `fetchUpstream: true`**: an unresolved, gated version's real verification
(a `GET` to the real registry's `/-/npm/v1/attestations/<name>@<version>`, then
cryptographic verification -- see [Verification](#verification) below) runs in
the background (see
[Fast-tier / background verification](#fast-tier--background-verification)
below); a `GET` to the attestations route for a package with nothing stored
locally relays the raw upstream response instead of 404ing -- **for the
requesting identity's own request**, see below.

The two "not yet known" outcomes -- missing `dist.integrity` to verify against,
and `fetchUpstream` being disabled or effectively disabled for this request --
are deliberately **not** persisted to storage or cached past the single request
that produced them: turning `fetchUpstream` on later, or a subsequent read that
does have `dist.integrity`, gets a real re-attempt rather than a permanently
calcified bad verdict from before the missing piece was available.

### Per-request override: `verdaccio-offline-enforcer` identities never trigger a live fetch

`fetchUpstream: true` is a whole-deployment default, but a single Verdaccio
process can serve two different kinds of caller with two different real network
postures -- a developer's own `npm install` typically has live internet access,
while a CI/CD job's own dependency installs are often deliberately air-gapped
(no upstream fallback at all, so a build only ever resolves packages already
known locally) via
[`verdaccio-offline-enforcer`](https://github.com/fortmesa/verdaccio-offline-enforcer)'s
online/offline identity policy. The static `fetchUpstream` config can't express
that distinction by itself.

So the actual, per-request answer to "is a live fetch allowed right now" is:
`fetchUpstream` config **AND** this specific request's identity is not
offline-restricted, per `verdaccio-offline-enforcer`'s own online/offline policy
-- read directly from that plugin's `middlewares:` config section
(`options.config.middlewares['@fortmesa/verdaccio-offline-enforcer']`), not from
any runtime signal `verdaccio-offline-enforcer` produces. (Its own gating can
swallow a request internally without ever calling `next()`, and this plugin's
own `GET /-/npm/v1/attestations/...` route is always exempted by that plugin's
own `/-/` passthrough rule -- there's no shared middleware-ordering point both
plugins could rely on for a runtime signal to work in every case; config-sharing
was verified to work in every case, a runtime signal was verified NOT to.)

This plugin duplicates `verdaccio-offline-enforcer`'s tiny `_isRestricted()`
matching logic (name/group vs. `online`/`offline` sets, `online` always wins,
`enforceForAnonymous`/`enforceForUnknown` deciding everyone else -- see that
plugin's own docs for the exact semantics) against the _same_ config values,
rather than sharing code across the two packages. **`verdaccio-offline-enforcer`
does not need to be installed or enabled at all** -- if its config section is
absent, every request behaves exactly as `fetchUpstream` alone says, using that
plugin's own documented defaults (`enforceForAnonymous: true`,
`enforceForUnknown: false`) as if an empty `online`/`offline` list were
configured.

These two plugins are maintained together; a config-shape change on
`verdaccio-offline-enforcer`'s side (its `online`/`offline` keys were already
renamed once from `onlineUsernames`/`offlineUsernames`) is expected to come with
a matching update here, not defended against with a compatibility shim.

A non-HTTP code path (e.g. Verdaccio's own web-UI package listing) has no
request/identity to evaluate at all -- `fetchUpstream` is treated as `false`
there regardless of config, the same fail-closed default `enforceForAnonymous`
already establishes for an anonymous HTTP request.

## Fast-tier / background verification

Checking one version's attestation status never blocks on network I/O for
another. `filter_metadata()` only ever awaits a strictly non-network resolution
tier per gated version:

1. **Peek** -- the packument's own `dist.attestations.verified` (already
   embedded, e.g. from a local publish this same process handled), or an
   in-memory cache hit from a verdict this process already resolved.
2. **Fast** -- peek, plus (on a cache miss) exactly one persisted-storage read
   of the object described in
   [Storage design](#storage-design-one-object-per-packageversion) below --
   still no network, no cryptographic verification, cheap enough to pay on every
   metadata read.

A version with no answer at either tier is **failed closed immediately**
(consistent with "`block` means require proof; no proof yet available also means
no") and the real resolution -- which may include the upstream fetch
`fetchUpstream` gates, plus actual `sigstore.verify()` cryptographic work -- is
kicked off as an untracked-by-the-request background `Promise`. A subsequent
metadata read for the same version sees the real verdict once that background
work finishes, without ever having blocked the request that triggered it.
Because each gated version resolves independently via `Promise.all`, and each
unresolved one's background work is independent too, none of this serializes
across a package's versions -- resolving version `A` never delays version `B`.

The plugin exposes `whenAllBackgroundWorkSettles()` for exactly one purpose:
letting a test deterministically await every in-flight background verification
(including ones triggered by others already in flight) instead of guessing a
timeout for `sigstore.verify()`'s own, sometimes network-bound, work to finish.
Real request handling never calls it.

## Verification

`verify.js` verifies a single Sigstore bundle against the package it's supposed
to belong to, and never throws -- always returns `{verified, reason}` (or
`{verified: true, predicateType}`), so one malformed/invalid bundle can't take
down whichever caller is checking it:

1. The bundle's DSSE envelope payload is parsed as an in-toto statement.
2. `statement.predicateType` must be a SLSA provenance predicate
   (`https://slsa.dev/provenance/v0.2` or `.../v1`). npm's own keyed "publish
   attestation" (`https://github.com/npm/attestation/.../publish/v0.1`) is
   deliberately **not** accepted here -- it's signed with npm's own registry
   key, not verified against Sigstore/Fulcio's public trust root, a narrower
   guarantee (registry-side publish integrity, not build provenance) than what
   "attested" means for this plugin's purposes.
3. `statement.subject[0].name` must match the package's own purl
   (`pkg:npm/<name>@<version>`, built via `npm-package-arg`).
4. `statement.subject[0].digest.sha512` must match the package's
   `dist.integrity`, parsed to a hex digest via `ssri`.
5. Only after all of the above pass does it call the real
   `sigstore.verify(bundle, opts)` -- actual cryptographic verification against
   Sigstore's public trust root, not an existence-only check. `opts` is whatever
   `sigstore:` is configured to in `filters:` (see [Full config](#full-config)
   above), passed straight through.

A `GET /-/npm/v1/attestations/...`-shaped response can carry more than one
attestation (real npm data for an attested package lists the keyed publish
attestation _first_ and the SLSA provenance one _second_).
`verifyAttestationsResponse()` tries each in order until one verifies, and
returns the bundle that actually produced the verdict alongside it -- a caller
that needs to persist "the bundle this verdict is about" cannot assume
`attestations[0]` is it.

## Storage design: one object per package@version

Exactly **one** stored object per package version -- not a separate marker file
alongside a raw bundle. Object-storage backends (this deployment's own S3 usage
included) typically bill per object with a real minimum regardless of content
size, so a second, often-tiny file per version would be a genuine cost at this
data's scale. Named `<name-with-/-replaced-by-->-<version>.attestation`,
alongside the tarball in the same per-package storage location, holding
`{verified, bundle, reason}` (`reason` present only when `verified: false`) --
the verdict is a field in the object's own contents, not encoded in its
filename, so a lookup is a single hit-or-miss, never two attempts to tell "known
bad" apart from "never checked".

### Why `storage.localStorage`, not `storage` directly

`register_middlewares(app, auth, storage)`'s `storage` parameter is Verdaccio
core's top-level orchestrating `Storage` class -- and its own
`addTarball`/`getTarball` must **never** be used for this plugin's verdict
storage. `Storage.getTarball()`, on any miss, automatically falls back to
syncing metadata from the uplink, which re-invokes every registered filter's
`filter_metadata()` -- including this plugin's own. Since a version's very first
fast-tier storage check is _guaranteed_ to miss (nothing has been persisted
yet), calling `Storage.getTarball()` from inside `filter_metadata()` recurses
into itself without end. This is real, confirmed behavior (a real Verdaccio
process hangs indefinitely this way, for a purely local package with zero
uplinks configured too -- not specific to proxied packages), not a theoretical
concern.

`storage.localStorage` is a different, lower-level class Verdaccio's own
`Storage` wraps -- a plain, ordinary (non-private) property -- whose own
`addTarball`/`getTarball`/`removeTarball` are thin wrappers directly over
whatever storage plugin is actually configured (filesystem or S3), with no
uplink fallback and no filter re-check at all. This plugin uses that instead,
via the same generic interface every Verdaccio storage backend implements --
deliberately not S3-specific object metadata or tags, so behavior is identical
regardless of which backend a deployment is configured with.
`storage.localStorage` has existed under that exact name since Verdaccio 2.3.0
(2017), unchanged through the 3.0 TypeScript rewrite and the 5→6 major version
jump -- stable in practice, though it is an internal implementation detail
Verdaccio's plugin API does not formally document or guarantee.

### In-memory-only fallback

If no `storage.localStorage` is reachable at all -- this plugin's own
`filters:`/`middlewares:` instance never received one via `register_middlewares`
(see the constructor comment on `PLUGIN_CONFIG_KEY` for why Verdaccio
instantiates this plugin twice, once per role, and only the `middlewares:`
instance ever receives `storage`), and no sibling instance in the same process
has either -- every storage read/write degrades silently to the in-memory
verdict cache alone, rather than throwing. Verification still works correctly
for the lifetime of that one process; it simply doesn't survive a restart, and
every replica ends up separately re-verifying a given package@version at least
once on its own.

### Verdict lifecycle matches its tarball's, deliberately never more

A stored verdict is treated as inseparable from the real tarball it corresponds
to -- it is not expired, deduplicated, or independently garbage-collected on any
timer. The guiding principle: **this plugin never resolves a lifecycle gap that
Verdaccio core itself leaves unresolved for the real tarball** -- it matches
Verdaccio's own behavior, it does not improve on it.

- **Full package removal** (`npm unpublish <pkg> --force`) already cleans this
  up for free, today, no code needed: Verdaccio's own `removePackage()` deletes
  every `_attachments` entry, and this plugin's stored object is registered as
  just another attachment (`addTarball`'s own success handler does this,
  regardless of caller).
- **A single tarball's dedicated delete**
  (`DELETE /:package/-/:filename/-rev/:revision`) is intercepted the same way
  publish is, and removes the correspondingly-named verdict object too.
- **Single-version unpublish, package otherwise unchanged** (a `PUT` with one
  fewer version than before) is deliberately **not** handled -- Verdaccio's own
  `changePackage()` doesn't delete the real tarball in this case either, only
  clears a bookkeeping field, so this plugin's verdict is allowed to go orphaned
  exactly when the real tarball would too. This was investigated for a subtler
  correctness risk (Verdaccio doesn't prevent republishing the exact same
  version number after this kind of unpublish, unlike real npmjs.org's own
  policy) and confirmed safe: Verdaccio's own `addVersion()` separately checks
  the real tarball attachment's retained shasum and rejects a republish with
  genuinely different content outright, and this plugin's own publish
  interception never persists a verdict for a rejected publish either. An
  orphaned verdict here is inert, not incorrect.
- Deliberately **no TTL-based expiration**: a verified Sigstore verdict is a
  permanent cryptographic fact, not something that goes stale with time (the
  short-lived Fulcio certificate involved is checked against the Rekor
  transparency log's own recorded signing time, never wall-clock "now" -- this
  is exactly what makes Sigstore verification valid indefinitely). Expiring a
  correct verdict would only mean redoing identical work later for zero benefit,
  so it is not done.
- Out-of-band storage edits bypassing Verdaccio's own HTTP API entirely (a
  manual restore, a hand-edited object) are unobservable to any hook-based
  plugin and are not something this design accounts for.

**Pod-restart durability**: with `storage.localStorage` reachable (see above), a
verdict persisted before a restart is found on the very _first_ metadata read
afterward, at the fast tier described above -- a fresh process's empty in-memory
cache is irrelevant, since the persisted object is checked before ever falling
back to the (background-only) real resolution. No re-fetch, no re-verification.
Without `storage.localStorage` reachable, see
[In-memory-only fallback](#in-memory-only-fallback) above instead -- this
guarantee does not hold.

## Proxy support

Mirrors [`verdaccio-audit`](https://www.npmjs.com/package/verdaccio-audit)'s own
`ProxyAudit` exactly: a plain `https.Agent` by default (`strict_ssl` controlling
certificate validation, default `true`), replaced by an `HttpsProxyAgent`
whenever `auth.config.https_proxy` is set -- Verdaccio's own uplink proxy
setting, read from the same `auth` object every plugin's
`register_middlewares()` receives. This means a firewalled/corporate deployment
that already routes outbound npm traffic through a specific proxy gets the same
behavior here as it does for Verdaccio's own uplinks, with no separate proxy
config for this plugin.

## Publish-time interception

A `PUT` to the publish route is intercepted by a middleware that runs **before
Verdaccio's own router** even mounts (so `req.params.package` does not exist yet
-- the package name is parsed directly from `req.path` instead), and before
Verdaccio's own body-parser installs, so this plugin parses the request body
itself.

**Why this has to happen before Verdaccio's own handling**: Verdaccio's core
publish handler's `hasDiffOneKey()` check hard-rejects any publish whose
`_attachments` has more than one key -- which is exactly what a real
`npm publish --provenance` sends (the tarball, plus a `.sigstore` bundle).
Without this interception, provenance-enabled publishes to a registry running
this plugin would fail outright today.

If the incoming body has no `_attachments` at all, or none of its keys end in
`.sigstore`, the request passes through untouched (this also naturally leaves
non-publish requests to the same route, like `npm deprecate`/`npm star`, alone).
Otherwise:

1. The `.sigstore` attachment's base64 payload is parsed as a Sigstore bundle.
   An unparseable attachment is dropped (logged as a `warn`) and the publish
   proceeds with no attestation recorded, rather than failing the publish over a
   malformed attachment.
2. The bundle is verified via [`verifyBundle()`](#verification) against the
   published version's own `dist.integrity` -- a version with no
   `dist.integrity` present yet fails verification with an explicit reason
   rather than skipping the check.
3. The bundle and verdict are persisted via the same
   [single-object storage](#storage-design-one-object-per-packageversion)
   proxied packages use, and the in-memory verdict cache is populated
   immediately -- a locally-published package's own next metadata read never
   needs to touch storage at all.
4. `dist.attestations = {url, verified, reason, predicateType}` is injected
   directly into the request body's version metadata, and the `.sigstore` key is
   deleted from `_attachments` -- down to exactly one attachment, so Verdaccio's
   own `hasDiffOneKey()` check now passes, and Verdaccio's own `addVersion()`
   persists the injected `dist.attestations` with no separate hook needed.

**A failed verification never blocks the publish itself** -- only the
`block`/`allow` enforcement filter (evaluated later, on read) can actually
prevent a bad or unattested version from being installed. This mirrors
`verdaccio-security-filter`'s own principle that a read-time filter and a
publish-time gate are separate, independently-toggled concerns; unlike that
plugin, this one currently has no dedicated publish-time _rejection_ gate for a
failed attestation -- a tampered or unverifiable `.sigstore` attachment is
recorded as `verified: false` and surfaced to the enforcement filter, not
refused at publish time.

## GET `/-/npm/v1/attestations/:pkgAtVersion` route

Serves the attestation bundle a real npm/yarn client requests after seeing
`dist.attestations.url` in a packument (`pacote` re-resolves that URL's _host_
to whichever registry is actually configured, which is why this request
naturally lands on this registry rather than the literal upstream host, even for
a proxied package).

`:pkgAtVersion` is split on the **last** `@` (the only unambiguous split point,
since a scoped package's own leading `@` is never the last one) after
URL-decoding.

Prefers whatever's already stored -- in the ordinary case, `filter_metadata()`
already ran on the packument fetch that surfaced this URL to the client in the
first place, so this is usually a hit. On a genuine miss, this relays the raw
upstream response (if `fetchUpstream` allows it -- see
[Per-request override](#per-request-override-verdaccio-offline-enforcer-identities-never-trigger-a-live-fetch)
above for what that means per-request; 404s otherwise) without caching it --
caching a verdict here would need the package's `dist.integrity` to verify
against, which a bare attestations `GET` doesn't carry.

## DELETE `/:package/-/:filename/-rev/:revision` route (tarball deletion)

Intercepted the same way `PUT` is -- a middleware parses `req.path` directly
(the package name and real tarball filename) rather than waiting for Verdaccio's
own router to populate `req.params`, since this middleware runs before that
router mounts. The real tarball's own filename is stripped of its package-name
prefix (scope excluded -- confirmed against a real npmjs.org response that a
scoped package's tarball filename omits the scope, e.g. `core-3.0.1.tgz` for
`@actions/core`) and `.tgz` suffix to recover the version, which is unambiguous
specifically because the package name is already known from the route, not
guessed from the filename alone.

Deferred to the response's own `finish` event and gated on a non-3xx status,
same as publish-time storage (see
[Publish-time interception](#publish-time-interception) above) -- a rejected
delete (e.g. permission denied) never triggers cleanup for a tarball that's
still actually there. See
[Verdict lifecycle matches its tarball's](#verdict-lifecycle-matches-its-tarballs-deliberately-never-more)
above for which deletion paths this plugin does and does not follow.

## Logging

Every read-time block logs a `warn`-level line
(`verdaccio-attestations: blocked -- ...`) including the package, version, and
reason. A successful publish-time verification logs at `info`; a failed one logs
at `warn`
(`verdaccio-attestations: publish attestation FAILED verification for ...`) --
neither is treated as loudly as `verdaccio-security-filter`'s own publish-time
gate rejections, since (as noted above) a failed attestation here doesn't stop
the publish, only records the verdict for the enforcement filter to act on
later. An unexpected failure serving the attestations route, or persisting a
verdict to storage, logs at `error`.

## Dependencies

`sigstore` -- real cryptographic bundle verification against Sigstore's public
trust root; the only dependency doing actual security work here, everything else
is plumbing around it. `minimatch` -- `block`/`allow` pattern matching, the same
convention Verdaccio core and `verdaccio-security-filter` both use. `semver` --
version-range scoping for `block`/`allow` rules, and sorting substitution
candidates for `strategy: replace`. `npm-package-arg` -- builds the purl an
attestation subject's name is checked against. `ssri` -- parses `dist.integrity`
into the hex digest an attestation subject's digest is checked against.
`node-fetch` -- upstream requests, only ever made when `fetchUpstream: true`.
`https-proxy-agent` -- proxy support for those requests (see
[Proxy support](#proxy-support) above), unused without `auth.config.https_proxy`
configured. `body-parser` -- parses the publish request body ahead of
Verdaccio's own parsing, to intercept a `.sigstore` attachment before
Verdaccio's `hasDiffOneKey()` check ever runs. Node's built-in
`node:async_hooks` (`AsyncLocalStorage`) -- carries the current request's
offline-restriction decision from `register_middlewares()` (real `req` access)
down into `filter_metadata()` and the attestations route handler (neither has
`req` access at all) -- no external package, but worth calling out since it's
load-bearing for the
[per-request fetchUpstream override](#per-request-override-verdaccio-offline-enforcer-identities-never-trigger-a-live-fetch).
