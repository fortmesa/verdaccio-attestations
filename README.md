# `verdaccio-attestations`

A supply-chain-provenance plugin for [Verdaccio](https://verdaccio.org): accepts
and stores npm provenance/[Sigstore](https://www.sigstore.dev/) attestations on
publish, serves them back to clients via the real npm attestations endpoint
(proxying and caching from upstream for non-local packages), and optionally
enforces that matching packages carry a cryptographically verified attestation
before they can be installed.

**Type**: Verdaccio `filter_metadata` plugin, and also a `middlewares` (Express)
plugin -- publish-time interception and the attestations GET route both require
a `storage` reference, which only `register_middlewares()` receives, so both
roles are always needed together (unlike
[`verdaccio-security-filter`](https://github.com/fortmesa/verdaccio-security-filter),
where the `middlewares` role is optional). **Config key** (the literal, scoped
package name -- Verdaccio never prefix-mangles a scoped plugin's config key):
`filters."@fortmesa/verdaccio-attestations"` and
`middlewares."@fortmesa/verdaccio-attestations"`, both reading from the
`filters:` section (see [Configuration](docs/configuration.md) for why).

## What it does

**On publish**, intercepts a `.sigstore` attachment before Verdaccio's own
publish handler ever sees it -- Verdaccio's `hasDiffOneKey()` check hard-rejects
any publish whose `_attachments` has more than one key, which is exactly what a
real `npm publish --provenance` sends (the tarball plus a `.sigstore` bundle).
The bundle is cryptographically verified (via the real
[`sigstore`](https://www.npmjs.com/package/sigstore) package, not an
existence-only check), stored, and the `.sigstore` attachment is stripped so the
publish itself always succeeds -- a failed verification is recorded, not
rejected, so a compromised or malformed attestation never blocks a legitimate
publish outright.

**On read**, serves a package's attestation via the real npm endpoint
(`GET /-/npm/v1/attestations/<name>@<version>`) -- preferring whatever's already
stored (from a local publish, or a verdict already computed for a proxied
package), and optionally relaying/caching from `registry.npmjs.org` for packages
this registry doesn't have local provenance for (see `fetchUpstream` below).

**Optionally, as an enforcement filter**: a `block`/`allow` list (same
minimatch + semver-range rule shape as `verdaccio-security-filter`) requires a
verified attestation for matching versions before they show up in package
metadata at all -- a version with no attestation, or one that fails
verification, is blocked identically ("no proof" and "disproven" are treated the
same way). Checking one version never blocks on network I/O for another: a fast,
zero-network tier (already-stored verdict, or an in-memory/persisted cache hit)
is all `filter_metadata()` ever awaits inline; anything not yet known is failed
closed immediately and resolved for real in the background, so one slow
verification never delays every other version's read.

See [`docs/configuration.md`](docs/configuration.md) for the full reference:
`block`/`allow` matching and `strategy: replace`, the `fetchUpstream` flag
(including its per-request override via `verdaccio-offline-enforcer`'s
online/offline identity policy) and why it defaults to `false`, the
single-object verdict storage design (and why), the fast-tier/background-
verification architecture, proxy support, and the publish/delete-time
interception mechanics.

## Installation

```bash
npm install @fortmesa/verdaccio-attestations
```

Verdaccio resolves a plugin by package name against whatever `plugins:` path
you've configured -- see Verdaccio's own docs on
[plugin resolution](https://verdaccio.org/docs/plugin-develop) if you're
installing into a custom global location rather than a project's `node_modules`.

## Quick config

```yaml
filters:
  '@fortmesa/verdaccio-attestations':
    fetchUpstream: false # see docs/configuration.md before enabling
    block:
      - '@your-scope/*'
    allow:
      - '@your-scope/known-unsigned-internal-tool'

middlewares:
  '@fortmesa/verdaccio-attestations': {}
```

See [`docs/configuration.md`](docs/configuration.md) for the full reference:
`block`/`allow` syntax (versions, `strategy: replace`), `fetchUpstream`,
`sigstore` verification options, proxy support, and storage/publish/GET-route
behavior.

## Testing

```bash
yarn install
yarn test
```

Runs a single hand-rolled `node:assert`-based smoke test file (no test
framework/build step) covering `verify.js`'s cryptographic verification (against
a real, captured `@actions/core@3.0.1` attestation fixture), `block`/`allow`
matching and substitution, the fast-tier/background verification split,
`fetchUpstream` gating (including its per-request `verdaccio-offline-enforcer`
override), proxy agent selection, publish/delete interception, the attestations
GET route, and several true end-to-end checks against a real Express app and
real HTTP requests. `yarn test:cli` drives real npm (8-11) and yarn (classic +
berry) binaries against a real running Verdaccio process, including a genuine
process-restart check that a verdict persisted via `storage.localStorage`
survives it.

## Dependencies

`sigstore` -- real cryptographic bundle verification against Sigstore's public
trust root. `minimatch` -- `block`/`allow` pattern matching, the same convention
Verdaccio's own `packages:` config and `@verdaccio/utils` use. `semver` --
version-range scoping for `block`/`allow` rules and sorting replacement
candidates. `npm-package-arg` -- builds the purl an attestation subject is
checked against. `ssri` -- parses `dist.integrity` into the digest an
attestation subject is checked against. `node-fetch` -- upstream requests when
`fetchUpstream` is enabled. `https-proxy-agent` -- proxy support for those
requests. `body-parser` -- parses the publish request body ahead of Verdaccio's
own parsing, to intercept a `.sigstore` attachment before Verdaccio's
`hasDiffOneKey()` check ever sees it.

## License

MIT -- see [LICENSE](LICENSE).
