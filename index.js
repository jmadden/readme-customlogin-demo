require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const basicAuth = require('basic-auth');
const readme = require('readmeio');
const app = express();

// Parse JSON and urlencoded (token endpoint needs form encoding)
app.use(express.json({ type: 'application/json' }));
app.use(express.urlencoded({ extended: false }));

/**
 * ----------------------------------------------------------------------------
 * Environment you need
 * ----------------------------------------------------------------------------
 * README_WEBHOOK_SECRET=...
 * README_JWT_SECRET=...                // for your /login → ReadMe JWT (unchanged)
 * README_HUB_URL=https://dash.readme.com/project/<yourproject>
 *
 * OAUTH_JWT_ISS=readme-demo-as          // JWT "iss"
 * OAUTH_JWT_AUD=widgetworks-api         // JWT "aud"
 * OAUTH_JWT_SECRET=supersecret-signing-key   // HS256 signing secret for bearer tokens
 *
 * DEMO_CLIENT_ID=demo-client
 * DEMO_CLIENT_SECRET=demo-secret
 * DEMO_REDIRECT_URI=http://localhost:3000/oauth/callback
 * ----------------------------------------------------------------------------
 */

// ============================================================================
// 1) Personalized Docs Webhook (unchanged)
// ============================================================================
app.post('/webhook', async (req, res) => {
  const signature = req.headers['readme-signature'];
  const secret = process.env.README_WEBHOOK_SECRET;

  try {
    readme.verifyWebhook(req.body, signature, secret);
  } catch (e) {
    return res.status(401).json({ error: e.message });
  }

  return res.json({
    name: 'Owlberto',
    email: req.body.email || 'owlberto@readme.com',
    keys: [
      { name: 'API Key - Server East', apiKey: '123456789', pass: 'hamburger' },
      { name: 'API Key - Server West', apiKey: '987654321' },
    ],
    servers: [
      { name: 'Demo API', url: 'https://readme-customlogin-demo.onrender.com' },
    ],
    avatar: 'https://placekitten.com/64/64',
  });
});

// ============================================================================
// 2) Custom Login to ReadMe (unchanged)
// ============================================================================
app.get('/login', (req, res) => {
  const user = {
    name: 'Owlberto',
    email: 'owlberto@readme.com',
    allowedProjects: ['your-readme-project'],
    redirect_url: '/jm-guides/docs/getting-started',
    api_key: 'api-key-12345-1',
    version: 1,
  };

  const auth_token = jwt.sign(user, process.env.README_JWT_SECRET);
  const targetUrl = `${
    process.env.README_HUB_URL
  }?auth_token=${auth_token}&redirect=${encodeURIComponent(user.redirect_url)}`;
  return res.redirect(targetUrl);
});

// Simple demo home page
app.get('/', (req, res) => {
  res.send(`<html>
    <body>
      <h1>Custom ReadMe Login + OAuth Demo</h1>
      <form action="/login" method="get"><button type="submit">Login to ReadMe Docs as Owlberto</button></form>
      <p>Auth Code Redirect URI for Try It!: <code>${process.env.DEMO_REDIRECT_URI}</code></p>
    </body>
  </html>`);
});

// ============================================================================
// 3) In-memory OAuth bits (demo-grade)
// ============================================================================

/** Registered demo client */
const clients = new Map([
  [
    process.env.DEMO_CLIENT_ID || 'demo-client',
    {
      client_id: process.env.DEMO_CLIENT_ID || 'demo-client',
      client_secret: process.env.DEMO_CLIENT_SECRET || 'demo-secret',
      redirect_uris: [
        process.env.DEMO_REDIRECT_URI ||
          'http://docs.triflecode.dev/oauth/callback',
      ],
      // which scopes a client can request via client_credentials
      cc_allowed_scopes: ['widgets:admin', 'read:widgets'],
    },
  ],
]);

/** Temporary auth code store: code -> { client_id, user, scope[], exp, pkce? } */
const codes = new Map();

/** “User database” – baked in for demo */
const demoUser = {
  sub: 'user_123',
  email: 'dev@example.com',
  name: 'Dev User',
  default_scopes: ['read:widgets', 'read:profile'],
};

/** Helpers */
const now = () => Math.floor(Date.now() / 1000);
function signAccessToken({ sub, scope, client_id, token_type = 'user' }) {
  return jwt.sign(
    {
      iss: process.env.OAUTH_JWT_ISS || 'readme-demo-as',
      aud: process.env.OAUTH_JWT_AUD || 'widgetworks-api',
      iat: now(),
      exp: now() + 3600, // 1 hour
      sub,
      client_id,
      scope: Array.isArray(scope) ? scope.join(' ') : scope,
      token_type, // "user" (auth code) or "service" (client credentials)
    },
    process.env.OAUTH_JWT_SECRET || 'supersecret-signing-key',
    { algorithm: 'HS256' }
  );
}

function parseScope(scopeStr, fallback = []) {
  if (!scopeStr) return fallback;
  return scopeStr.split(/[,\s]+/).filter(Boolean);
}

function verifyClientAuth(req, clientIdFromBody) {
  // HTTP Basic takes precedence
  const creds = basicAuth(req);
  if (creds && creds.name && creds.pass) {
    const rec = clients.get(creds.name);
    if (!rec || rec.client_secret !== creds.pass) return null;
    return rec;
  }
  // Body fallback (not recommended, but supported by ReadMe with x-readme option)
  if (clientIdFromBody) {
    const rec = clients.get(clientIdFromBody);
    if (!rec || rec.client_secret !== req.body.client_secret) return null;
    return rec;
  }
  return null;
}

// ============================================================================
// 4) Authorization Endpoint (Authorization Code flow, PKCE optional)
//    GET /oauth/authorize?response_type=code&client_id=...&redirect_uri=...&scope=...&state=...&code_challenge=...&code_challenge_method=S256
// ============================================================================
app.get('/oauth/authorize', (req, res) => {
  const {
    response_type,
    client_id,
    redirect_uri,
    scope: scopeStr,
    state,
    code_challenge,
    code_challenge_method,
  } = req.query;

  if (response_type !== 'code') {
    return res.status(400).send('unsupported_response_type');
  }

  const client = clients.get(String(client_id || ''));
  if (!client) return res.status(400).send('invalid_client');

  if (!client.redirect_uris.includes(redirect_uri)) {
    return res.status(400).send('invalid_redirect_uri');
  }

  // DEMO: auto-approve as “Owlberto” with requested scopes intersecting user defaults.
  const requested = parseScope(scopeStr, demoUser.default_scopes);
  const granted = Array.from(new Set([...requested])); // no real filtering here; keep demo simple

  const code = crypto.randomBytes(24).toString('hex');
  codes.set(code, {
    client_id: client.client_id,
    user: demoUser,
    scope: granted,
    exp: Date.now() + 5 * 60 * 1000, // 5 minutes
    pkce: code_challenge
      ? { code_challenge, method: code_challenge_method || 'S256' }
      : null,
  });

  const url = new URL(redirect_uri);
  url.searchParams.set('code', code);
  if (state) url.searchParams.set('state', state);

  return res.redirect(url.toString());
});

// ============================================================================
// 5) Token Endpoint (Auth Code + Client Credentials)
//    POST application/x-www-form-urlencoded to /oauth/token
// ============================================================================
app.post('/oauth/token', (req, res) => {
  const { grant_type } = req.body;

  // ---- client authentication (Basic or body) ----
  const client = verifyClientAuth(req, req.body.client_id);
  if (!client) {
    return res.status(401).json({ error: 'invalid_client' });
  }

  if (grant_type === 'authorization_code') {
    const { code, redirect_uri, code_verifier } = req.body;
    const record = codes.get(code);
    if (!record) return res.status(400).json({ error: 'invalid_grant' });
    if (record.client_id !== client.client_id)
      return res.status(400).json({ error: 'invalid_grant' });
    if (Date.now() > record.exp)
      return res
        .status(400)
        .json({ error: 'invalid_grant', error_description: 'code expired' });

    // PKCE check (optional)
    if (record.pkce) {
      if (!code_verifier)
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'missing code_verifier',
        });
      if (record.pkce.method === 'S256') {
        const hash = crypto.createHash('sha256').update(code_verifier).digest();
        const b64url = hash
          .toString('base64')
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=+$/, '');
        if (b64url !== record.pkce.code_challenge) {
          return res.status(400).json({
            error: 'invalid_grant',
            error_description: 'PKCE verification failed',
          });
        }
      } else {
        // plain (not recommended)
        if (code_verifier !== record.pkce.code_challenge) {
          return res.status(400).json({
            error: 'invalid_grant',
            error_description: 'PKCE verification failed',
          });
        }
      }
    }

    // OPTIONAL: you can validate redirect_uri here too if you stored it with code.

    // One-time use
    codes.delete(code);

    const token = signAccessToken({
      sub: record.user.sub,
      scope: record.scope,
      client_id: client.client_id,
      token_type: 'user',
    });

    return res.json({
      access_token: token,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: record.scope.join(' '),
    });
  }

  if (grant_type === 'client_credentials') {
    const requested = parseScope(req.body.scope, []);
    // limit to what this client is allowed to get
    const allowed = new Set(client.cc_allowed_scopes || []);
    const granted = requested.length
      ? requested.filter(s => allowed.has(s))
      : Array.from(allowed);

    if (!granted.length) {
      return res.status(400).json({ error: 'invalid_scope' });
    }

    const token = signAccessToken({
      sub: `client:${client.client_id}`,
      scope: granted,
      client_id: client.client_id,
      token_type: 'service',
    });

    return res.json({
      access_token: token,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: granted.join(' '),
    });
  }

  return res.status(400).json({ error: 'unsupported_grant_type' });
});

// A convenience callback endpoint for local manual testing
app.get('/oauth/callback', (req, res) => {
  const { code, state } = req.query;
  res.send(
    `<h2>Auth Code received</h2><pre>code=${code}\nstate=${state || ''}</pre>`
  );
});

// ============================================================================
// 6) Bearer auth + scope middleware for your API
// ============================================================================
function bearerAuth(requiredScopes = []) {
  return (req, res, next) => {
    const hdr = req.headers.authorization || '';
    const m = hdr.match(/^Bearer\s+(.+)$/i);
    if (!m) return res.status(401).json({ error: 'missing_bearer_token' });

    try {
      const payload = jwt.verify(
        m[1],
        process.env.OAUTH_JWT_SECRET || 'supersecret-signing-key',
        {
          algorithms: ['HS256'],
          audience: process.env.OAUTH_JWT_AUD || 'widgetworks-api',
          issuer: process.env.OAUTH_JWT_ISS || 'readme-demo-as',
        }
      );
      req.token = payload;
    } catch (e) {
      return res
        .status(401)
        .json({ error: 'invalid_token', details: e.message });
    }

    if (requiredScopes.length) {
      const tokenScopes = new Set(
        (req.token.scope || '').split(/\s+/).filter(Boolean)
      );
      const missing = requiredScopes.filter(s => !tokenScopes.has(s));
      if (missing.length) {
        return res.status(403).json({ error: 'insufficient_scope', missing });
      }
    }

    next();
  };
}

// ============================================================================
// 7) Demo API Endpoints (switched from x-api-key → Bearer + scopes)
//    Map these to your OpenAPI operation security:
//    - GET /api/hello, /api/data, /api/status → ["read:widgets"]
//    - GET /api/error → ["widgets:admin"]
// ============================================================================
function logApiCall(req, res) {
  // You can still log to ReadMe. Use token claims for labeling.
  const label = req.token
    ? `${req.token.token_type}:${req.token.sub} (scopes: ${
        req.token.scope || ''
      })`
    : 'anonymous';

  readme.log(process.env.README_API_KEY, req, res, {
    label,
    email: 'owlberto@readme.com',
  });
}

app.get('/api/hello', bearerAuth(['read:widgets']), (req, res) => {
  logApiCall(req, res);
  res.json({
    message: `Hello, ${req.token.sub}!`,
    scopes: req.token.scope || '',
  });
});

app.get('/api/data', bearerAuth(['read:widgets']), (req, res) => {
  logApiCall(req, res);
  res.json({
    data: [1, 2, 3, 4],
    tokenSubject: req.token.sub,
    description: 'Sample data array',
  });
});

app.get('/api/status', bearerAuth(['read:widgets']), (req, res) => {
  logApiCall(req, res);
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    tokenSubject: req.token.sub,
  });
});

app.get('/api/error', bearerAuth(['widgets:admin']), (req, res) => {
  logApiCall(req, res);
  res.status(500).json({ error: 'Something went wrong on the server.' });
});

// ============================================================================
// 8) Boot
// ============================================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Listening on http://localhost:${PORT}`));
