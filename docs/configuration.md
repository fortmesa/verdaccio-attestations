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
      # trustedPublishers: [] # optional -- see "Verification" below. ONLY
      # applied to a locally-published package's own .sigstore attachment,
      # never to a proxied third-party one. Each entry: {issuer?,
      # subjectAlternativeName?} -- at least one required, both allowed.
      # subjectAlternativeName is a real minimatch pattern (dot: true, so
      # "**"/"*" cross a leading-"." path segment like GitHub Actions' own
      # "/.github/workflows/" -- confirmed necessary against a real bundle,
      # not every glob library's default) matched against the verified
      # certificate's own identity -- not GitHub-specific, works for any
      # Sigstore-compatible issuer's own SAN shape:
      #   trustedPublishers:
      #     - subjectAlternativeName: 'https://github.com/fortmesa/verdaccio-attestations/**'
      #     - issuer: 'https://token.actions.githubusercontent.com'
      #       subjectAlternativeName: 'https://github.com/fortmesa/*/**'
      # signingKeys: [] # optional -- see "Registry signatures" below. One
      # secret directory path per entry (each a mounted cert-manager-style
      # kubernetes.io/tls Secret: tls.crt + tls.key), ECDSA P-256 only. Empty
      # (the default) means this deployment never signs a local publish with
      # its own registry key, regardless of trustedPublishers:
      #   signingKeys:
      #     - /var/run/secrets/verdaccio-attestations-signing-key

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
_every_ one of them says `replace`; otherwise the safer `remove` wins. A
substitute must be a version this same read gated and verified, so a version no
rule covers, which nothing checked, is never used, and a version whose key isn't
valid semver is neither used nor given a substitute. The blocked version's entry
becomes a copy of the substitute's whole version record with `version`
rewritten, minus `dist.signatures` and `dist.attestations`: both name the
substitute's own version, so under the blocked version's number they would fail
`npm audit signatures` and the attestation subject check. What actually gets
installed for that version number is the substitute's attested tarball.

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
cryptographic verification -- see [Verification](#verification) below) is
awaited directly by the request that needs it, bounded by a 5-second timeout
(see
[Fast-tier verification, awaited in full when it isn't already known](#fast-tier-verification-awaited-in-full-when-it-isnt-already-known)
below); a `GET` to the attestations route for a package with nothing stored
locally relays the raw upstream response instead of 404ing -- **for the
requesting identity's own request**, see below.

**Turning this on means trusting exactly what [Verification](#verification)
below checks, no more** -- a cryptographically valid Sigstore signature, backed
by a real transparency-log entry, over the exact package@version and tarball
being installed. It does **not** mean the signer's identity was checked against
the package's actual legitimate publisher -- see that section's "Known
limitation" for why that specifically can't be closed for a proxied, third-party
package (as opposed to a package published locally to this registry, where the
operator's own OIDC config already independently establishes who's trusted to
publish what).

Three outcomes are not verdicts, so none is cached or persisted: a missing
`dist.integrity` to verify against; `fetchUpstream` disabled or effectively
disabled for this request (an offline-restricted or anonymous caller, see
below); and a lookup or signature check that couldn't finish (a timeout, a 5xx
or network error from the uplink, or `sigstore.verify()` failing to refresh its
TUF trust root). Each is answered as unverified for that read only, so turning
`fetchUpstream` on, a read that has `dist.integrity`, or an online caller gets a
real attempt. After a failed lookup or check, the version isn't tried again for
60 seconds (`UPSTREAM_RETRY_BACKOFF_MS` in `index.js`), so an outage doesn't add
a 5-second wait to every read. An uplink answering 404 ("no attestation
upstream") is a verdict, and is cached in memory.

A package whose `packages:` entry has no `proxy` is never looked up upstream:
Verdaccio contacts no uplink for it, and sending a private package's name to the
public registry would leak it. Only a version string that's valid semver is
looked up, URL-encoded.

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

## Fast-tier verification, awaited in full when it isn't already known

Checking one version's attestation status never blocks on network I/O for
another version -- `filter_metadata()` resolves every gated version concurrently
(`Promise.all`), so version `A` never delays version `B`. Two tiers, evaluated
per version:

1. **Fast (no network)** -- an in-memory cache hit from a verdict this process
   already resolved, or (on a cache miss) exactly one persisted-storage read of
   the object described in
   [Storage design](#storage-design-one-object-per-packageversion) below --
   cheap enough to pay on every metadata read. Either counts only if it was
   computed for the version's current `dist.integrity`. The packument's own
   `dist.attestations.verified` is never read as a verdict: whoever publishes a
   version writes its metadata, so a publisher could set it to `true` on a
   version with no provenance at all.
2. **Real** -- for any version the fast tier has no answer for: the upstream
   fetch `fetchUpstream` gates (bounded by a 5-second timeout --
   `UPSTREAM_FETCH_TIMEOUT_MS` in `index.js` -- so a slow/unresponsive upstream
   can't turn a metadata read into a hang instead of a bounded wait), plus
   actual `sigstore.verify()` cryptographic work, which makes network calls of
   its own (a TUF trust-root refresh, with its own 5-second timeout and two
   retries) that this timeout doesn't cover. `filter_metadata()` awaits this
   directly rather than returning a fail-closed answer immediately and resolving
   it in the background: a never-before-seen version's _first_ read used to be
   guaranteed wrong (blocked, even for a package that would have verified
   cleanly) purely because nothing had checked it yet -- a real, confusing false
   negative for whichever client happened to be first, not just a one-time
   cold-cache cost.

Once resolved, a verdict is cached in memory and, when there's a bundle to keep,
persisted, so a second read of the same version never repeats the real
resolution. What isn't a verdict is never cached (see
[fetchUpstream and live upstream calls](#fetchupstream-and-live-upstream-calls)
above).

If anything inside `filter_metadata()` throws, every version a `block` rule
covers is removed from that response. Verdaccio's own filter runner catches a
filter's error and serves the packument it passed in, unfiltered, so letting the
error escape would serve every gated version.

The plugin exposes `whenAllBackgroundWorkSettles()` for the background work it
does -- `_interceptPublish()`'s deferred storage write after a local publish
(see [Publish-time interception](#publish-time-interception) below) and the
registry key refresh -- letting a test deterministically await it instead of
guessing a timeout. Real request handling never calls it.

## Verification

`verify.js` verifies a single Sigstore bundle against the package it's supposed
to belong to, and never throws -- always returns `{verified, reason}` (or
`{verified: true, predicateType}`), so one malformed/invalid bundle can't take
down whichever caller is checking it:

1. The bundle's DSSE envelope payload is parsed as an in-toto statement, which
   must be a JSON object.
2. `statement.predicateType` must be a SLSA provenance predicate
   (`https://slsa.dev/provenance/v0.2` or `.../v1`). npm's own keyed "publish
   attestation" (`https://github.com/npm/attestation/.../publish/v0.1`) is
   deliberately **not** accepted here -- it's signed with npm's own registry
   key, not verified against Sigstore/Fulcio's public trust root, a narrower
   guarantee (registry-side publish integrity, not build provenance) than what
   "attested" means for this plugin's purposes.
3. `statement.subject[0].name` must match the package's own purl
   (`pkg:npm/<name>@<version>`, built via `npm-package-arg`).
4. `dist.integrity` must be exactly one `sha512-<base64>` entry, which is what
   npm writes, and `statement.subject[0].digest.sha512` must match it. An SRI
   string can list several hashes, and a client accepts a tarball that matches
   any of them, so a second sha512 entry would let one tarball be attested and
   another installed. Any other integrity string fails verification.
5. Only after all of the above pass does it call the real
   `sigstore.verify(bundle, opts)` -- actual cryptographic verification against
   Sigstore's public trust root, not an existence-only check. `opts` is whatever
   `sigstore:` is configured to in `filters:` (see [Full config](#full-config)
   above), passed straight through. A `VerificationError`, `PolicyError` or
   `ValidationError` from it is the verdict. Any other error (a `TUFError` when
   the trust root can't be refreshed, an `InternalError`) means the check didn't
   finish, so the result is marked transient and never recorded as a verdict.

**Signer identity: checkable for a locally-published package, not for a proxied
one.** `sigstore.verify()` alone only confirms the bundle is a cryptographically
genuine Sigstore signature backed by a real Rekor transparency-log entry -- with
no `certificateIdentityEmail`/
`certificateIdentityURI`/`certificateIssuer`/`certificateOIDs` set under
`sigstore:` (the default, `{}`), it accepts a valid signature from _any_
Sigstore identity, not specifically the package's own legitimate publisher.

For a package published **locally** (`_interceptPublish()`,
[Publish-time interception](#publish-time-interception) below),
`sigstore.trustedPublishers` closes this: a small list of
`{issuer?, subjectAlternativeName?}` entries (see [Full config](#full-config)
above) that the verified certificate's own identity must match at least one of,
checked _after_ `sigstore.verify()` succeeds (since `sigstore.verify()` itself
only supports one static identity constraint, not "any of N" -- this plugin
checks the returned, already-cryptographically-verified `Signer`'s identity
against the whole list instead). This is meaningful specifically because the
operator already has an independent, trusted answer to "who's allowed to publish
this" -- the same small set of repos already enumerated in
`verdaccio-oidc-auth`'s own `allow:` list.

**Deliberately not offered for a proxied, third-party package** -- there's no
equivalent independent answer for an arbitrary npm package this registry merely
proxies:

- **No independent source of truth.** There's no registry-maintainable mapping
  of "the legitimate GitHub repo for every third-party npm package." A field
  embedded in the very packument being verified (e.g. `repository.url`) isn't
  independent of it -- an attacker who has already compromised a package's real
  publish credentials controls that field too, so checking identity against it
  would be circular, not a security boundary.
- **No stable identity to pin to, even in principle.** Fulcio certificates are
  short-lived (~10 minutes) and minted fresh per signing operation, tied to that
  one ephemeral build's exact OIDC claims -- there's no persistent, checkable
  "this is always package X's identity" the way a traditional long-lived
  code-signing certificate would provide.
- **The upstream registry contributes no opinion of its own either** --
  confirmed directly against a real captured response
  (`test/fixtures/actions-core-3.0.1-attestations.json`):
  `GET /-/npm/v1/attestations/...` returns only `predicateType`/`bundle`/
  `signedAccessSignatureUrl`, no `verified`/`valid` field anywhere. It's a plain
  relay of whatever was attached at publish time -- every check above is this
  plugin's own, entirely independent of anything npm's registry asserts.

What `verified: true` therefore actually proves, for a proxied package: a real,
OIDC-authenticated Sigstore identity -- traceable, permanently, in a public
transparency log -- attested that this exact tarball came from some automated
build pipeline. It does not prove that identity is the package's legitimate
maintainer. That's the real ceiling of what SLSA provenance can prove for an
arbitrary third-party package with no independently-trusted identity to check
against, not a gap specific to this plugin's own implementation.

A `GET /-/npm/v1/attestations/...`-shaped response can carry more than one
attestation (real npm data for an attested package lists the keyed publish
attestation _first_ and the SLSA provenance one _second_).
`verifyAttestationsResponse()` tries each in order until one verifies, and
returns the bundle that actually produced the verdict alongside it -- a caller
that needs to persist "the bundle this verdict is about" cannot assume
`attestations[0]` is it. A response whose `attestations` isn't an array, or an
entry without a bundle object, fails verification instead of throwing; when no
entry verifies and any failed transiently, the whole result is transient.

## Registry signatures

A **completely separate mechanism** from everything in
[Verification](#verification) above, easy to conflate with it but answering a
different question. SLSA provenance attestations (what `verifyBundle()` checks)
are Sigstore/Fulcio-based, opt-in per package (only a `--provenance` publish
carries one), and keyless. npm's own **registry signature** scheme
(`dist.signatures` on a version's metadata, verified against
`GET /-/npm/v1/keys`) is npm-registry-key-based, **universal**
(`registry.npmjs.org` signs every package it hosts, whether or not that package
also carries SLSA provenance), and is what
`npm audit signatures`/`npm install`'s own signature check actually reads for
the common case of an ordinary, non-attested proxied package.

**Why this registry needs to participate in it at all.** Verdaccio's own core
uplink-proxying already relays a proxied package's `dist.signatures` field
verbatim -- that part needs no code here. What's missing is the other half of
that check: `GET /-/npm/v1/keys`, which a real npm/yarn client always queries
against **whatever registry it's configured against** (this one), never the
literal upstream host. Without this registry serving that route at all,
`npm audit signatures` fails outright -- confirmed directly:

```
npm error code EMISSINGSIGNATUREKEY
npm error fast-deep-equal@3.1.3 has a registry signature with keyid:
SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA but no corresponding
public key can be found
```

for `fast-deep-equal@3.1.3` -- an ordinary proxied package with no SLSA
attestation at all, so `fetchUpstream`/`sigstore.trustedPublishers` were never
even in play. `npm audit signatures` uses `p-map` with `stopOnError: true`
internally, so this single missing key aborts the _entire_ audit run, not just
the one package.

### `GET /-/npm/v1/keys`

Registered unconditionally (same as the attestations route), serving, in this
order:

1. This deployment's own configured `sigstore.signingKeys` (see
   [Registry-signing a local publish](#registry-signing-a-local-publish) below),
   if any.
2. Every upstream registry signing key this deployment has relayed (see
   [Upstream key relay](#upstream-key-relay) below).

### Upstream key relay

Fetches `GET /-/npm/v1/keys` from **every** configured uplink (`config.uplinks`,
not scoped to any one package's own `proxy:` list the way attestation fetches
are -- a registry signing key isn't package-specific, so every configured
uplink's keys are relayed, not just the ones some already-known package happens
to use), on an unref'd, self-rescheduling timer (every 6 hours, plus an
immediate first run on startup) started from `register_middlewares()`.

**Deliberately not gated behind `fetchUpstream`**, unlike every other upstream
call this plugin makes. `fetchUpstream` governs whether _this plugin_ verifies
SLSA attestations -- an opt-in, narrower feature. The registry signature this
key relay supports is already being relayed unconditionally by Verdaccio's own
core proxying, with or without `fetchUpstream`. Gating the key relay on
`fetchUpstream` (default `false`) would mean the signature keeps flowing through
by default while the corresponding key never does -- reproducing the exact
`EMISSINGSIGNATUREKEY` failure above for every proxied package, on the default
config. This is a narrower, different kind of always-on network call than
`fetchUpstream`'s own documented promise ("never contacts registry.npmjs.org
directly unless explicitly opted into") covers -- it only ever fetches
`/-/npm/v1/keys` itself, nothing else, from uplinks this deployment is already
configured to proxy from for ordinary installs.

A fetch failure for one uplink never prevents another uplink's keys from being
relayed.

A client looks a signature's key up by `keyid` alone and takes the first match,
so two rules keep one source from answering for another. A `keyid` matching one
of this registry's own `signingKeys` is never taken from an uplink. A `keyid`
already relayed from one uplink is refused from any other, and a different key
under the same `keyid` logs a warning; the first uplink keeps it until restart.

Relayed keys live in memory only. After a restart, the refresh that runs at
startup fills them in again; until it succeeds (say, while npmjs.org is
unreachable), only this registry's own keys are served, and
`npm audit signatures` reports `EMISSINGSIGNATUREKEY` for proxied packages.

### Registry-signing a local publish

`sigstore.signingKeys` (see [Full config](#full-config) above) configures one or
more ECDSA P-256 signing keys this deployment owns, each provisioned the same
way any other TLS secret in this org's Kubernetes deployments is: a
cert-manager-managed `kubernetes.io/tls` Secret, mounted as a directory
containing `tls.crt`/`tls.key`. Multiple entries are supported specifically so a
key rotation can add a new key alongside an old one, rather than requiring an
atomic swap -- both remain valid, both get served at `GET /-/npm/v1/keys`, until
the old secret is actually removed from config.

**Generating a key/cert pair for local development or testing** (an operator's
real deployment should provision this the same way as any other TLS secret, via
cert-manager -- this is for anyone who needs a standalone pair without a
cluster, e.g. running this plugin locally):

```sh
openssl ecparam -name prime256v1 -genkey -noout -out tls.key
openssl req -new -x509 -key tls.key -out tls.crt -days 3650 -subj "/CN=verdaccio-attestations-signing-key"
```

Only the curve (`prime256v1`, i.e. P-256) and key type (EC) matter to this
plugin -- the certificate's subject, validity window (beyond a real `expires`),
and issuer are never checked against anything; the certificate here exists only
to carry the public key and a validity end date (surfaced as `expires` in the
served `publicKeyEntry`), not to establish any identity the way a
Sigstore/Fulcio certificate does. At startup the plugin signs and verifies a
test message with each pair, and refuses to start if `tls.key` doesn't match the
public key in `tls.crt`: every signature it produced would otherwise fail
`EINTEGRITYSIGNATURE` downstream.

**When signing actually happens**: only during
[publish-time interception](#publish-time-interception), and only when **both**
`sigstore.signingKeys` is configured **and** `sigstore.trustedPublishers` is
configured _and matched_ for that specific publish -- not merely "the
attestation verified". A signature that verified with `trustedPublishers` left
unconfigured (so no identity was actually checked) proves the tarball came from
_some_ Sigstore-authenticated build, not that it came from a publisher this
deployment actually trusts -- registry- signing that with our own key would let
a downstream `npm audit signatures` treat it as equally trustworthy as a real
`trustedPublishers` match, which it isn't. `sigstore.signingKeys` configured
with `sigstore.trustedPublishers` left empty therefore signs nothing, ever --
the same permissive-by-default posture this plugin's other opt-in features
already have.

The signed message is `<name>@<version>:<dist.integrity>` (the exact template
real npm/pacote signs and verifies against -- confirmed directly against
`pacote`'s own verification source -- using the raw SRI-format integrity string,
e.g. `sha512-...`, not a hex digest), producing
`dist.signatures: [{keyid, sig}, ...]`, one entry per configured signing key,
injected into the same version metadata `dist.attestations` already is.

**Deliberately not offered for a proxied, third-party package.** Only a local
publish's own freshly-computed `dist.integrity` is ever signed with our own key
-- re-signing an upstream package's own already-relayed content was considered
and rejected: it would require re-deriving a signature over content this plugin
doesn't control end-to-end (a `block`/`allow` filter or some other plugin could
still mutate the packument after the fact), and would carry a different, weaker
semantic meaning for a package with no `trustedPublishers` identity vetting
behind it at all -- see
[Deliberately not offered for a proxied, third-party package](#deliberately-not-offered-for-a-proxied-third-party-package)
above for the identical reasoning already established for identity-pinning.

## Storage design: one object per package@version

Exactly **one** stored object per package version -- not a separate marker file
alongside a raw bundle. Object-storage backends (this deployment's own S3 usage
included) typically bill per object with a real minimum regardless of content
size, so a second, often-tiny file per version would be a genuine cost at this
data's scale. Named `<name-with-/-replaced-by-->-<version>.attestation`,
alongside the tarball in the same per-package storage location, holding
`{verified, integrity, bundle, reason}` (`reason` present only when
`verified: false`) -- the verdict is a field in the object's own contents, not
encoded in its filename, so a lookup is a single hit-or-miss, never two attempts
to tell "known bad" apart from "never checked".

`integrity` is the `dist.integrity` the verdict was computed for, and the object
counts only while it matches the version's current `dist.integrity`. Objects
written by 1.1.x and earlier carry no `integrity`, so they are ignored and the
version is resolved again: a proxied one through `fetchUpstream`, while a local
one stays unverified until it's republished with provenance.

A local publish whose `sigstore.verify()` couldn't finish (see
[Verification](#verification)) still stores its bundle, as
`{verified: false, transient: true, identityChecked, integrity, bundle, reason}`.
Such an object is not a verdict: the next read verifies the stored bundle again
(no uplink involved), applying `trustedPublishers` if `identityChecked` says the
publish did, and caches that outcome in memory.

These objects are the registry's own. A client's
`PUT /:package/-/<name>.attestation/...`, a publish body with an `.attestation`
attachment, and a `DELETE` of an `.attestation` file all get a 403, since
Verdaccio would otherwise store or remove whatever a publisher sends under that
name.

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
(2017), unchanged through the 3.0 TypeScript rewrite and the 5-to-6 major
version jump -- stable in practice, though it is an internal implementation
detail Verdaccio's plugin API does not formally document or guarantee.

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
back to the real resolution. No re-fetch, no re-verification. Without
`storage.localStorage` reachable, see
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
config for this plugin. An `http://` uplink gets a plain `http.Agent`, without
the proxy.

This covers the plugin's own requests (attestation lookups and the key relay),
not `sigstore.verify()`'s. Each verification refreshes Sigstore's TUF trust root
from `tuf-repo-cdn.sigstore.dev` through Node's built-in `fetch`, which ignores
`https_proxy`. A deployment whose only way out is that proxy needs one of:
direct egress to that host; Node started with `--use-env-proxy` (24.5 and later,
which 22.12 doesn't have) and `HTTPS_PROXY` set; or the
`tufMirrorURL`/`tufCachePath`/`tufForceCache` options under `sigstore:`, which
go straight to `sigstore.verify()`. Without one of those, every verification
fails transiently: nothing is recorded as a verdict, and gated versions stay
blocked.

## Publish-time interception

A `PUT` to the publish route is intercepted by a middleware that runs **before
Verdaccio's own router** even mounts (so `req.params.package` does not exist yet
-- the package name is parsed directly from `req.path` instead, in both the
encoded `/@scope%2Fpkg` and the unencoded `/@scope/pkg` form). When Verdaccio
hasn't already parsed the body, this plugin parses it with its own
`body-parser`: `application/json` only, up to `max_body_size` (413 past it),
with malformed JSON answered 400.

Verdaccio checks publish permission only in its own router, after every plugin
middleware has run. So this plugin asks it first (`auth.allow_publish`), and
does nothing for a request Verdaccio would refuse: no verification, no cached
verdict, no network call. The request passes through for Verdaccio to reject.

**Why this has to happen before Verdaccio's own handling**: Verdaccio's core
publish handler's `hasDiffOneKey()` check hard-rejects any publish whose
`_attachments` has more than one key -- which is exactly what a real
`npm publish --provenance` sends (the tarball, plus a `.sigstore` bundle).
Without this interception, provenance-enabled publishes to a registry running
this plugin would fail outright today.

If the incoming body has no `_attachments` and `versions` objects, the request
passes through untouched (this also naturally leaves non-publish requests to the
same route, like `npm deprecate`/`npm star`, alone). For a real publish,
`dist.attestations` and `dist.signatures` are first removed from every version
in the body, since only this plugin writes them. If no attachment key ends in
`.sigstore`, that's all. Otherwise:

1. The `.sigstore` attachment's `data` is parsed directly as a JSON Sigstore
   bundle -- unlike every other attachment (including the tarball itself), this
   one is a **raw string, not base64**. Confirmed directly against real source,
   not assumed: identical in npm CLI's own `libnpmpublish` (every version that
   supports `--provenance` -- 9.9.4, 10.9.8, 11.18.0 all checked, zero
   variation) and in Yarn's `@yarnpkg/plugin-npm` (v3.7.0, which explicitly
   ports npm's own implementation) -- both embed `JSON.stringify(bundle)`
   directly, since a JSON string is already safe to embed in a JSON body without
   an extra encoding layer (unlike the tarball's raw binary, which genuinely
   needs one). An unparseable attachment is dropped (logged as a `warn`) and the
   publish proceeds with no attestation recorded, rather than failing the
   publish over a malformed attachment.
2. The uploaded tarball attachment is decoded and checked against the published
   version's `dist.integrity`, which must be a single sha512 entry (see
   [Verification](#verification)). The client writes that field, and Verdaccio
   checks only the sha1 `shasum`, and only when one is sent; a mismatch fails
   verification (and so nothing is signed). Then the bundle is verified via
   [`verifyBundle()`](#verification) against `dist.integrity` -- a version with
   no `dist.integrity` present yet fails verification with an explicit reason
   rather than skipping the check.
3. Once Verdaccio has accepted the publish (its response finishes with a status
   below 300), the bundle and verdict are persisted via the same
   [single-object storage](#storage-design-one-object-per-packageversion)
   proxied packages use, and the in-memory verdict cache is populated, so a
   locally-published package's own next metadata read never needs to touch
   storage at all. A publish Verdaccio rejects leaves neither behind.
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

The route runs the same access check Verdaccio's own `GET /:package` does
(`auth.allow_access`) and answers a denial with its status, so a package
restricted to some users doesn't have its versions, tarball digests and build
identities readable by everyone through this route.

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
still actually there. A successful one also drops the version's in-memory
verdict. A `DELETE` naming an `.attestation` file itself gets a 403. See
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
attestation subject's name is checked against. Node's own `node:http` and
`node:https` make the upstream requests: attestation fetches, only ever made
when `fetchUpstream: true`, and the
[upstream registry key relay](#upstream-key-relay)'s `GET /-/npm/v1/keys`
requests, which are unconditional (see that section for why). Each request uses
the agent described under [Proxy support](#proxy-support) and follows up to 20
redirects. `https-proxy-agent` -- proxy support for those requests (see
[Proxy support](#proxy-support) above), unused without `auth.config.https_proxy`
configured. `body-parser` -- parses the publish request body when Verdaccio
hasn't already, to intercept a `.sigstore` attachment before Verdaccio's
`hasDiffOneKey()` check ever runs. It stays on 1.x, the major Verdaccio's own
`express` 4 uses, with the same range, so one copy is installed. Node's built-in
`node:async_hooks` (`AsyncLocalStorage`) -- carries the current request's
offline-restriction decision from `register_middlewares()` (real `req` access)
down into `filter_metadata()` and the attestations route handler (neither has
`req` access at all) -- no external package, but worth calling out since it's
load-bearing for the
[per-request fetchUpstream override](#per-request-override-verdaccio-offline-enforcer-identities-never-trigger-a-live-fetch).
Node's built-in `node:crypto` -- all of `keys.js`'s own cryptography (loading an
ECDSA P-256 key/cert pair, computing a keyid, signing a registry signature) --
see [Registry signatures](#registry-signatures) above; no external package
needed since Node's own `crypto` module already covers everything that mechanism
requires.
