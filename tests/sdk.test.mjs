import test from 'node:test';
import assert from 'node:assert/strict';
import {
  HybridTlsClient,
  HybridTlsServer,
  bytesToHex,
  hexToBytes,
  bytesToBase64Url,
  base64UrlToBytes
} from '../dist/index.js';

test('Hybrid TLS SDK: Hex and Base64Url Wire Encoding Round-Trip', () => {
  const bytes = new Uint8Array([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]);
  const hex = bytesToHex(bytes);
  assert.equal(hex, '123456789abc');
  assert.deepEqual(hexToBytes(hex), bytes);
  assert.deepEqual(hexToBytes('0x123456789abc'), bytes);

  const b64 = bytesToBase64Url(bytes);
  assert.deepEqual(base64UrlToBytes(b64), bytes);
});

test('Hybrid TLS SDK: End-to-End Client & Server Handshake and Bidirectional Session Transport', () => {
  const client = new HybridTlsClient();
  const server = new HybridTlsServer();

  // 1. Client starts handshake
  const { clientKeyShareBase64Url } = client.startHandshake();
  assert.equal(typeof clientKeyShareBase64Url, 'string');

  // 2. Server processes and returns server key share + server session
  const { serverKeyShareBase64Url, session: serverSession } = server.handleClientKeyShare(clientKeyShareBase64Url);
  assert.equal(typeof serverKeyShareBase64Url, 'string');

  // 3. Client completes handshake and receives client session
  const clientSession = client.completeHandshake(serverKeyShareBase64Url);

  // 4. Client sends encrypted request to Server
  const reqRecord = clientSession.send('GET /status HTTP/1.1');
  const serverReceived = serverSession.receive(reqRecord);
  assert.equal(new TextDecoder().decode(serverReceived), 'GET /status HTTP/1.1');

  // 5. Server responds to Client
  const respRecord = serverSession.send('HTTP/1.1 200 OK');
  const clientReceived = clientSession.receive(respRecord);
  assert.equal(new TextDecoder().decode(clientReceived), 'HTTP/1.1 200 OK');
});

test('Hybrid TLS SDK: Adversarial Negative Control - Replay Attack Detection via Sequence Numbers', () => {
  const client = new HybridTlsClient();
  const server = new HybridTlsServer();

  const { clientKeyShareBase64Url } = client.startHandshake();
  const { serverKeyShareBase64Url, session: serverSession } = server.handleClientKeyShare(clientKeyShareBase64Url);
  const clientSession = client.completeHandshake(serverKeyShareBase64Url);

  const reqRecord = clientSession.send('First Payload');
  serverSession.receive(reqRecord); // Consumes seq 0n

  // Attacker attempts to replay the same record
  assert.throws(
    () => serverSession.receive(reqRecord),
    /SEQUENCE_NUMBER_MISMATCH/
  );
});

test('Hybrid TLS SDK: Adversarial Negative Control - Incomplete Handshake Guard', () => {
  const uninitializedClient = new HybridTlsClient();
  assert.throws(
    () => uninitializedClient.completeHandshake(new Uint8Array(1120)),
    /HANDSHAKE_STATE_INVALID/
  );
});
