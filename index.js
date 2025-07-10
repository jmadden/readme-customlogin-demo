require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const readme = require('readmeio');
const app = express();

app.use(express.json({ type: 'application/json' }));

app.post('/webhook', async (req, res) => {
  const signature = req.headers['readme-signature'];
  const secret = process.env.README_WEBHOOK_SECRET;

  try {
    readme.verifyWebhook(req.body, signature, secret);
  } catch (e) {
    return res.status(401).json({ error: e.message });
  }

  // For demo, always return mocked personalized data
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
    // Add any other user info or variables you want!
  });
});

app.get('/login', (req, res) => {
  // This is your fake, static user for the demo
  const user = {
    name: 'Owlberto',
    email: 'owlberto@readme.com',
    // allowedProjects and redirect_url are optional, but shown for completeness
    allowedProjects: ['your-readme-project'], // use your real project slug if needed
    redirect_url: '/jm-guides/docs/getting-started', // docs path after login, can customize
    api_key: 'api-key-12345-1', // demo, only if you want it prefilled in API Explorer
    version: 1, // REQUIRED by ReadMe
  };

  // Sign the JWT with your ReadMe JWT secret
  const auth_token = jwt.sign(user, process.env.README_JWT_SECRET);

  // Build the redirect URL
  const targetUrl = `${
    process.env.README_HUB_URL
  }?auth_token=${auth_token}&redirect=${encodeURIComponent(user.redirect_url)}`;

  // Redirect user to ReadMe, logging them in
  return res.redirect(targetUrl);
});

// Optional: serve a basic HTML button for logging in (for demo UX)
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

app.get('/api/hello', (req, res) => {
  // ...existing API key logic...
  if (!['123456789', '987654321'].includes(req.headers['x-api-key'])) {
    return res.status(401).json({ error: 'Invalid or missing API key' });
  }
  // Log the request/response to ReadMe (requires your project API Key)
  readme.log(process.env.README_API_KEY, req, res, {
    apiKey: req.headers['x-api-key'],
    label: 'Owlberto',
    email: 'owlberto@readme.com',
  });
  res.json({
    message: `Hello, developer! Your key ${req.headers['x-api-key']} is valid.`,
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Listening on http://localhost:${PORT}`));
