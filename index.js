require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const readme = require('readmeio');
const app = express();

app.use(express.json({ type: 'application/json' }));

// -----------------------------
// Personalized Docs Webhook
// -----------------------------
app.post('/webhook', async (req, res) => {
  const signature = req.headers['readme-signature'];
  const secret = process.env.README_WEBHOOK_SECRET;

  try {
    readme.verifyWebhook(req.body, signature, secret);
  } catch (e) {
    return res.status(401).json({ error: e.message });
  }

  // Mocked personalized data
  return res.json({
    name: 'Owlberto',
    email: req.body.email || 'owlberto@readme.com',
    keys: [
      {
        name: 'API Key - Server East',
        apiKey: '123456789',
        pass: 'hamburger',
      },
      {
        name: 'API Key - Server West',
        apiKey: '987654321',
      },
    ],
    servers: [
      { name: 'Demo API', url: 'https://readme-customlogin-demo.onrender.com' },
    ],
    avatar: 'https://placekitten.com/64/64',
  });
});

// -----------------------------
// Custom Login
// -----------------------------
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

// -----------------------------
// Demo Login Page
// -----------------------------
app.get('/', (req, res) => {
  res.send(`<html>
    <body>
      <h1>Custom ReadMe Login Demo</h1>
      <form action="/login" method="get">
        <button type="submit">Login to ReadMe Docs as Owlberto</button>
      </form>
    </body>
  </html>`);
});

// -----------------------------
// Centralized API Key Middleware
// -----------------------------
const validKeys = ['123456789', '987654321'];
function apiKeyCheck(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  if (!validKeys.includes(apiKey)) {
    return res.status(401).json({ error: 'Invalid or missing API key' });
  }
  req.apiKey = apiKey; // Attach for later use/logging
  next();
}

// -----------------------------
// Demo API Endpoints (all logged)
// -----------------------------
function logApiCall(req, res) {
  readme.log(process.env.README_API_KEY, req, res, {
    apiKey: req.apiKey,
    label: `API Key: ${req.apiKey}`,
    email: 'owlberto@readme.com',
  });
}

app.get('/api/hello', apiKeyCheck, (req, res) => {
  logApiCall(req, res);
  res.json({
    message: `Hello, ${req.name}! Your key ${req.apiKey} is valid.`,
  });
});

app.get('/api/data', apiKeyCheck, (req, res) => {
  logApiCall(req, res);
  res.json({
    data: [1, 2, 3, 4],
    requestedBy: req.apiKey,
    description: 'Sample data array',
  });
});

app.get('/api/status', apiKeyCheck, (req, res) => {
  logApiCall(req, res);
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    apiKeyUsed: req.apiKey,
  });
});

app.get('/api/error', apiKeyCheck, (req, res) => {
  logApiCall(req, res);
  // Simulate a server error
  res.status(500).json({ error: 'Something went wrong on the server.' });
});

// -----------------------------

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Listening on http://localhost:${PORT}`));
