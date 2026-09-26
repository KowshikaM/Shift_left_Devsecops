const assert = require('node:assert/strict');
const { after, before, test } = require('node:test');
const { once } = require('node:events');
const { createApp } = require('./index');

let server;
let baseUrl;

before(async () => {
  server = createApp().listen(0, '127.0.0.1');
  await once(server, 'listening');
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  if (server) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
});

test('health endpoint reports the service as available', async () => {
  const response = await fetch(`${baseUrl}/health`);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { status: 'ok' });
});

test('user endpoint continues to respond to an id parameter', async () => {
  const response = await fetch(`${baseUrl}/user?id=42`);
  assert.equal(response.status, 200);
  assert.match(await response.text(), /users/);
});
