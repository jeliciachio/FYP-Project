import * as OpenIDClient from './OpenIDClient.mjs';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import Router from '@koa/router';


// Load config.json from project root
const __filename = fileURLToPath(import.meta.url);
const configPath = path.join(__filename, '../../../../config.json');
let rawConfig = {};
try {
  rawConfig = JSON.parse(fs.readFileSync(configPath));
  console.info('[INFO]: config is imported.');
} catch (e) {
  console.error('[ERROR]: facing error when parsing config.', e);
}

const config = {
  singpass: {
    client_id: rawConfig.CLIENT_ID,
    issuer: rawConfig.ISSUER_URL,
    redirect_uri: rawConfig.REDIRECT_URI,
    scopes: rawConfig.SCOPES,
    keys: rawConfig.KEYS || {},
  },
};

// OIDC client setup
let client;
console.log('Starting OIDC client setup...');
(async () => {
  try {
    // Convert PRIVATE_SIG_KEY from config to JWK format for openid-client
    const privateJwk = {
      ...config.singpass.keys.PRIVATE_SIG_KEY
    };
    console.log('[DEBUG] Private JWK used for OIDC client:', privateJwk);
    client = await OpenIDClient.discovery(
      new URL(config.singpass.issuer),
      config.singpass.client_id,
      privateJwk,
      OpenIDClient.None()
    );
    console.log('[DEBUG] OIDC client initialized:', !!client);
    if (client) {
      console.log('[DEBUG] OIDC client keys:', Object.keys(client));
    }
  } catch (err) {
    console.error('[OIDC CLIENT INIT ERROR]', err);
  }
})();

const router = new Router();

// Route to initiate Singpass OIDC login
router.get('/auth/singpass', async (ctx) => {
  if (!client) {
    ctx.status = 503;
    ctx.body = 'OIDC client not ready. Please try again in a moment.';
    return;
  }
  // PKCE code verifier/challenge
  const code_verifier = OpenIDClient.randomPKCECodeVerifier();
  const code_challenge = await OpenIDClient.calculatePKCECodeChallenge(code_verifier);

  // Build the authorization URL manually
  const state = OpenIDClient.randomState();
  const nonce = OpenIDClient.randomNonce();

  // Store PKCE, state, and nonce in session for callback validation
  ctx.session.code_verifier = code_verifier;
  ctx.session.state = state;
  ctx.session.nonce = nonce;

  // Debug: print session values at login
  console.log('[DEBUG /auth/singpass] code_verifier:', code_verifier);
  console.log('[DEBUG /auth/singpass] state:', state);
  console.log('[DEBUG /auth/singpass] nonce:', nonce);

  const url = OpenIDClient.buildAuthorizationUrl(client, {
    response_type: 'code',
    client_id: config.singpass.client_id,
    redirect_uri: config.singpass.redirect_uri,
    scope: config.singpass.scopes,
    state,
    nonce,
    code_challenge,
    code_challenge_method: 'S256',
  });
  ctx.redirect(url);
});

router.get('/callback', async (ctx) => {
  try {
    const receivedQueryParams = ctx.request.query;

    const code_verifier = ctx.session.code_verifier;
    const state = ctx.session.state;
    const nonce = ctx.session.nonce;

    // Debug: print session values at callback
    console.log('[DEBUG /callback] code_verifier:', code_verifier);
    console.log('[DEBUG /callback] state:', state);
    console.log('[DEBUG /callback] nonce:', nonce);

    const tokenSet = await client.callback(config.singpass.redirect_uri, receivedQueryParams, {
      code_verifier,
      state,
      nonce,
    });
    console.log('These are the claims in the ID token:');
    console.log(tokenSet.claims());

    const userInfo = await client.userinfo(tokenSet);
    console.log('This is the user info returned:');
    console.log(userInfo);

    ctx.session.user = { ...tokenSet.claims(), ...userInfo };
    ctx.redirect('/');
  } catch (err) {
    console.error('[OIDC CALLBACK ERROR]', err);
    if (err.response) {
      try {
        const body = await err.response.text();
        console.error('[OIDC CALLBACK ERROR RESPONSE BODY]', body);
        ctx.body = 'Error during callback: ' + err.message + '\n' + body;
      } catch (e) {
        ctx.body = 'Error during callback: ' + err.message + '\n[Could not read error response body]';
      }
    } else {
      ctx.body = 'Error during callback: ' + err.message;
    }
    ctx.status = 401;
  }
});

router.get('/user', function getUser(ctx) {
  if (ctx.session.user) {
    ctx.body = ctx.session.user;
  } else {
    ctx.status = 401;
  }
});

router.get('/logout', function handleLogout(ctx) {
  ctx.session = null;
  ctx.redirect('/');
});


export default router;
