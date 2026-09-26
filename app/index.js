const express = require('express');
function createApp() {
  const app = express();

  app.get('/user', (req, res) => {
    const userId = req.query.id;

    // INTENTIONAL DEMO VULNERABILITY #2: SQL injection pattern
    // SAST (Semgrep) should flag string-concatenated queries.
    const query = "SELECT * FROM users WHERE id = '" + userId + "'";

    res.send(`Would run query: ${query}`);
  });

  app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
  });

  return app;
}

const app = createApp();

if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`Demo app listening on port ${port}`));
}

module.exports = { app, createApp };
