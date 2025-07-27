// Minimal custom OpenIDClient utility for Singpass demo compatibility
import { Issuer, generators } from 'openid-client';

export async function discovery(issuerUrl, client_id, client_secret, none) {
  const issuer = await Issuer.discover(issuerUrl.toString());
  return new issuer.Client({
    client_id,
    redirect_uris: [],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
  });
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
