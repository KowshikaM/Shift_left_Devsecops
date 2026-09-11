const express = require('express');
const app = express();

// INTENTIONAL DEMO VULNERABILITY #1: hardcoded secret
// Gitleaks / secret scanning should catch this and fail the build.
const API_KEY = "AKIAABCDEFGHIJKLMNOP"; // fake AWS-style key for demo purposes

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

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Demo app listening on port ${port}`));
