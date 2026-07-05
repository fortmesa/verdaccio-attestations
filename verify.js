'use strict';

const sigstore = require('sigstore');
const npa = require('npm-package-arg');
const ssri = require('ssri');

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

// Verifies a single raw Sigstore bundle (the exact shape a publish
// attachment carries, and the shape of each entry in a GET
// /-/npm/v1/attestations/... response's attestations[].bundle) against the
// package it's supposed to belong to. Never throws -- returns
// {verified, reason} so one malformed/invalid bundle can't take down
// whichever caller is checking it. predicateType is read from the parsed
// statement itself, not a caller-supplied label, since the publish-time
// attachment carries no such label at all.
async function verifyBundle({name, version, integrity}, bundle, opts = {}) {
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

  try {
    await sigstore.verify(bundle, opts);
  } catch (err) {
    return {
      verified: false,
      reason: `signature verification failed: ${err.message}`,
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
  SLSA_PROVENANCE_PREDICATE_TYPES,
};
