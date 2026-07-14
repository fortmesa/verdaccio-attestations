'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

// npm's own registry-signature scheme (dist.signatures / GET
// /-/npm/v1/keys) is a completely separate mechanism from the Sigstore/SLSA
// provenance attestations the rest of this plugin handles -- see
// docs/configuration.md's "Registry signatures" section for why both exist
// and what each one actually proves. This module is the only place that
// touches it: loading our own signing key(s), computing a keyid for them,
// signing a package's integrity string, and normalizing whatever a real
// registry's own /-/npm/v1/keys response looks like into the same shape we
// store our own keys in.

const KEY_TYPE = 'ecdsa-sha2-nistp256';

// Matches the real registry.npmjs.org's own keyid shape (confirmed directly
// against a live response: "SHA256:<43-char base64, no padding>") --
// SHA256 over the DER-encoded SubjectPublicKeyInfo, base64, padding
// stripped. This is purely a lookup label under our own control on both
// ends (we set it when signing, we set it again when serving
// /-/npm/v1/keys; a client only ever does a string match between the two,
// never independently recomputes it -- confirmed against pacote's own
// verification source), so exact algorithmic conformance to some external
// standard isn't security-load-bearing -- it only has to be a stable,
// reproducible function of the public key, which this is.
function computeKeyId(publicKeyObject) {
  const der = publicKeyObject.export({type: 'spki', format: 'der'});
  const digest = crypto.createHash('sha256').update(der).digest('base64');
  return `SHA256:${digest.replace(/=+$/, '')}`;
}

// One entry per configured secret directory -- see
// docs/configuration.md's "Registry signatures" section for the expected
// directory shape (a mounted cert-manager-style kubernetes.io/tls Secret:
// tls.crt + tls.key files) and the openssl command to hand-generate an
// equivalent pair for local/dev use. Deliberately does not generate a key
// itself anywhere in this codebase -- provisioning a real private key is
// an operational/secret-management concern, not something this plugin
// should be doing on an operator's behalf.
function loadSigningKey(secretDir) {
  const keyPath = path.join(secretDir, 'tls.key');
  const certPath = path.join(secretDir, 'tls.crt');
  const privateKey = crypto.createPrivateKey(fs.readFileSync(keyPath));
  const cert = new crypto.X509Certificate(fs.readFileSync(certPath));
  const publicKey = cert.publicKey;

  if (privateKey.asymmetricKeyType !== 'ec') {
    throw new Error(
      `verdaccio-attestations: signing key at ${keyPath} is a ` +
        `'${privateKey.asymmetricKeyType}' key -- only ECDSA P-256 ` +
        `(${KEY_TYPE}) is supported, matching npm's own registry-signature scheme`,
    );
  }
  const curve = privateKey.asymmetricKeyDetails?.namedCurve;
  if (curve !== 'prime256v1' && curve !== 'P-256') {
    throw new Error(
      `verdaccio-attestations: signing key at ${keyPath} uses curve ` +
        `'${curve}' -- only P-256 (prime256v1) is supported, matching ` +
        `npm's own registry-signature scheme`,
    );
  }

  const keyid = computeKeyId(publicKey);
  const expires = cert.validTo ? new Date(cert.validTo).toISOString() : null;

  return {
    keyid,
    expires,
    // message: "<name>@<version>:<integrity>" -- the exact template real
    // npm/pacote signs and verifies against (confirmed directly against
    // both the verification source and npm's own documentation).
    sign(message) {
      const signer = crypto.createSign('SHA256');
      signer.write(message);
      signer.end();
      return signer.sign(privateKey, 'base64');
    },
    // The shape a GET /-/npm/v1/keys response entry needs -- key is the
    // raw SPKI DER, base64, no PEM armor (matching the real registry's own
    // response shape, confirmed directly against a live
    // registry.npmjs.org response).
    publicKeyEntry: {
      expires,
      keyid,
      keytype: KEY_TYPE,
      scheme: KEY_TYPE,
      key: publicKey.export({type: 'spki', format: 'der'}).toString('base64'),
    },
  };
}

// Fails loud at construction on a bad path/malformed key -- same principle
// as compileRules()/compileTrustedPublishers() above: a misconfigured
// signing key should never silently mean "no signing happens", since an
// operator who configured this expects it to actually be in effect.
function loadSigningKeys(secretDirs) {
  return secretDirs.map(loadSigningKey);
}

// Normalizes one upstream registry's real GET /-/npm/v1/keys response
// (already confirmed directly against a live registry.npmjs.org response)
// into the same {keyid, expires, keytype, scheme, key} shape our own keys'
// publicKeyEntry already uses, so both can be stored/served identically
// downstream.
function normalizeUpstreamKeysResponse(body) {
  const keys = Array.isArray(body?.keys) ? body.keys : [];
  return keys
    .filter(k => typeof k?.keyid === 'string' && typeof k?.key === 'string')
    .map(k => ({
      keyid: k.keyid,
      expires: k.expires ?? null,
      keytype: typeof k.keytype === 'string' ? k.keytype : KEY_TYPE,
      scheme: typeof k.scheme === 'string' ? k.scheme : KEY_TYPE,
      key: k.key,
    }));
}

// A keyid ("SHA256:<base64>") contains "/" and "+" whenever the underlying
// base64 digest does -- both unsafe as a bare storage filename segment
// (directory traversal risk for "/", and no benefit to preserving "+"/"="
// verbatim either). This is a lookup-safe encoding only, never decoded back
// -- the index file (see index.js's registry-keys storage) is what maps a
// filename back to its real keyid.
function keyStorageFilename(keyid) {
  const safe = keyid.replace(/[^A-Za-z0-9]/g, '_');
  return `key-${safe}.json`;
}

module.exports = {
  KEY_TYPE,
  computeKeyId,
  loadSigningKeys,
  normalizeUpstreamKeysResponse,
  keyStorageFilename,
};
