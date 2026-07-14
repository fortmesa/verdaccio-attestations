'use strict';

const sigstore = require('sigstore');
const npa = require('npm-package-arg');
const ssri = require('ssri');
const {minimatch} = require('minimatch');

// The SLSA provenance predicate is the one that actually proves build/source
// linkage (keyless, verified against Sigstore's own public trust root) --
// this is what "attested" means for this plugin's purposes. npm's separate
// "publish attestation" (predicateType .../npm/attestation/.../publish/v0.1)
// is signed with npm's own registry key instead of Sigstore/Fulcio, a
// distinct, narrower guarantee (registry-side publish integrity, not build
// provenance) -- verified against a real bundle (@actions/core@3.0.1):
// sigstore.verify() fails it out of the box with "key not found", since
// that key belongs to npm's own infrastructure, not Sigstore's trust root.
// Not required here; only the provenance predicate is.
const SLSA_PROVENANCE_PREDICATE_TYPES = new Set([
  'https://slsa.dev/provenance/v0.2',
  'https://slsa.dev/provenance/v1',
]);

// Not GitHub-specific -- deliberately mirrors this codebase's own
// established convention (verdaccio-oidc-auth's entirely config-driven
// verifier, this same plugin's block:/allow: minimatch rules): each entry
// is a real minimatch pattern matched against the verified certificate's own
// `identity.subjectAlternativeName` (a URI whose shape is entirely up to
// whichever OIDC issuer minted it -- GitHub Actions' own is
// "https://github.com/<owner>/<repo>/.github/workflows/<file>@<ref>",
// confirmed directly against a real captured bundle
// (test/fixtures/actions-core-3.0.1-attestations.json), but GitLab CI,
// CircleCI, or any other Sigstore-compatible issuer mints its own different
// shape -- this plugin doesn't need to know any of them, only the operator
// configuring `trustedPublishers` does), with an optional `issuer` field
// (matched against `identity.extensions.issuer`, e.g.
// "https://token.actions.githubusercontent.com") to also pin which OIDC
// issuer must have minted it.
function matchesTrustedPublisher(identity, trustedPublishers) {
  if (!identity) return false;
  return trustedPublishers.some(entry => {
    if (entry.issuer && identity.extensions?.issuer !== entry.issuer) {
      return false;
    }
    if (entry.subjectAlternativeName) {
      const san = identity.subjectAlternativeName;
      if (typeof san !== 'string') return false;
      // dot: true -- minimatch's default *-exclusion for a path segment
      // starting with "." (its own dotfile convention) would otherwise
      // silently prevent every "**"/"*" pattern from ever matching a real
      // GitHub Actions SAN at all: confirmed directly, GitHub's own SAN
      // shape always routes through a literal "/.github/workflows/" segment
      // (see the real captured example above), which minimatch treats like
      // a hidden file unless told not to. Not GitHub-specific in effect --
      // any other issuer's SAN with its own dot-segment would hit the same
      // silent non-match without this.
      if (!minimatch(san, entry.subjectAlternativeName, {dot: true})) {
        return false;
      }
    }
    return true;
  });
}

// Verifies a single raw Sigstore bundle (the exact shape a publish
// attachment carries, and the shape of each entry in a GET
// /-/npm/v1/attestations/... response's attestations[].bundle) against the
// package it's supposed to belong to. Never throws -- returns
// {verified, reason} so one malformed/invalid bundle can't take down
// whichever caller is checking it. predicateType is read from the parsed
// statement itself, not a caller-supplied label, since the publish-time
// attachment carries no such label at all.
//
// trustedPublishers (an array of {issuer?, subjectAlternativeName?} entries
// -- see matchesTrustedPublisher() above) is optional and, when given,
// requires the signing certificate's own identity to match at least one
// entry. See docs/configuration.md's "Verification" section for why this is
// only meaningful for a locally-published package (the caller for a
// proxied, third-party one must never pass this: there's no independent,
// not-also-attacker-controlled source of truth for "the legitimate identity
// for an arbitrary third-party package").
async function verifyBundle(
  {name, version, integrity},
  bundle,
  opts = {},
  trustedPublishers = null,
) {
  let purl;
  try {
    purl = npa.toPurl(npa(`${name}@${version}`));
  } catch (err) {
    return {verified: false, reason: `invalid package spec: ${err.message}`};
  }

  let statement;
  try {
    statement = JSON.parse(
      Buffer.from(bundle.dsseEnvelope.payload, 'base64').toString('utf8'),
    );
  } catch (err) {
    return {
      verified: false,
      reason: `unparseable attestation payload: ${err.message}`,
    };
  }

  if (!SLSA_PROVENANCE_PREDICATE_TYPES.has(statement.predicateType)) {
    return {
      verified: false,
      reason: `not a SLSA provenance attestation (predicateType: ${statement.predicateType})`,
    };
  }

  const subject = statement.subject?.[0];
  if (!subject) {
    return {verified: false, reason: 'no subject in attestation payload'};
  }
  if (subject.name !== purl) {
    return {
      verified: false,
      reason: `attestation subject ${subject.name} does not match package ${purl}`,
    };
  }

  let integrityHexDigest;
  try {
    integrityHexDigest = ssri.parse(integrity).hexDigest();
  } catch (err) {
    return {
      verified: false,
      reason: `invalid integrity string: ${err.message}`,
    };
  }
  if (subject.digest?.sha512 !== integrityHexDigest) {
    return {
      verified: false,
      reason:
        'attestation subject digest does not match package tarball integrity',
    };
  }

  // `opts` (from `sigstore:` config, default `{}`) confirms the signature is
  // cryptographically genuine and Rekor-logged -- it does NOT, by default,
  // check WHOSE identity signed it (certificateIdentityEmail/
  // certificateIdentityURI/certificateIssuer/certificateOIDs, all unset).
  // Deliberately not fixable for a proxied third-party package via `opts`
  // itself: there's no independent (i.e. not also attacker-controlled once
  // publish credentials are compromised) source of truth for "the
  // legitimate repo for package X". trustedPublishers below is the
  // *locally-published* case's answer instead -- a small, operator-curated
  // list, checked against the verified certificate's own identity after the
  // fact, not passed into sigstore.verify() itself (which only supports one
  // static identity constraint, not "any of N").
  let signer;
  try {
    signer = await sigstore.verify(bundle, opts);
  } catch (err) {
    return {
      verified: false,
      reason: `signature verification failed: ${err.message}`,
    };
  }

  if (
    trustedPublishers &&
    !matchesTrustedPublisher(signer.identity, trustedPublishers)
  ) {
    return {
      verified: false,
      reason: `signed by an identity not in the trusted publisher list (${signer.identity?.subjectAlternativeName ?? 'no identity on this certificate'})`,
    };
  }

  return {verified: true, predicateType: statement.predicateType};
}

// Tries each bundle in a GET /-/npm/v1/attestations/... style response
// ({attestations: [{bundle}, ...]}) until one verifies as a valid SLSA
// provenance attestation (a package can carry other attestation types
// alongside it, e.g. npm's own keyed "publish attestation" -- see above).
// Returns the bundle actually used alongside the verdict -- real npm data
// (verified against @actions/core@3.0.1) lists the keyed publish-attestation
// FIRST and the provenance one second, so a caller that needs to persist
// "the bundle this verdict is about" cannot assume entries[0] is it.
async function verifyAttestationsResponse(
  pkg,
  attestationsResponse,
  opts = {},
) {
  const entries = attestationsResponse?.attestations ?? [];
  if (entries.length === 0) {
    return {
      verified: false,
      reason: 'no attestations present',
      bundle: undefined,
    };
  }
  let lastResult;
  for (const {bundle} of entries) {
    const result = await verifyBundle(pkg, bundle, opts);
    if (result.verified) return {...result, bundle};
    lastResult = {...result, bundle};
  }
  return lastResult;
}

module.exports = {
  verifyBundle,
  verifyAttestationsResponse,
  matchesTrustedPublisher,
  SLSA_PROVENANCE_PREDICATE_TYPES,
};
