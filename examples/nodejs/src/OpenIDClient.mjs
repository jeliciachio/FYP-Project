// Minimal custom OpenIDClient utility for Singpass demo compatibility
import { Issuer, generators } from 'openid-client';
import { importJWK } from 'jose';

export async function discovery(issuerUrl, client_id, client_private_jwk, none) {
  const issuer = await Issuer.discover(issuerUrl.toString());
  // Create a keystore and add the private JWK
  // Import the private JWK as a key
  const privateKey = await importJWK(client_private_jwk, client_private_jwk.alg);
  const client = new issuer.Client({
    client_id,
    redirect_uris: [],
    response_types: ['code'],
    token_endpoint_auth_method: 'private_key_jwt',
    keys: [privateKey],
  });
  return client;
}

export function randomState() {
  return generators.state();
}

export function randomNonce() {
  return generators.nonce();
}

export function randomPKCECodeVerifier() {
  return generators.codeVerifier();
}

export function calculatePKCECodeChallenge(verifier) {
  return generators.codeChallenge(verifier);
}

export function buildAuthorizationUrl(client, params) {
  return client.authorizationUrl(params);
}

export function None() {
  return undefined;
}
