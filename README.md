# @qmoosa/pqc-hybrid-tls-sdk

[![CI Gate](https://github.com/elon00/qmoosa-pqc-hybrid-tls-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/elon00/qmoosa-pqc-hybrid-tls-sdk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> QMOOSA Post-Quantum Cryptography Suite — Hybrid Post-Quantum TLS Client SDK & Secure Session Transport.

## Overview

`@qmoosa/pqc-hybrid-tls-sdk` provides ergonomic client and server abstractions for executing hybrid post-quantum key exchange (X25519 + ML-KEM-768) and managing bidirectional authenticated AES-256-GCM sessions with monotonic sequence number tracking.

## Usage

```typescript
import { HybridTlsClient, HybridTlsServer } from '@qmoosa/pqc-hybrid-tls-sdk';

// Client starts handshake
const client = new HybridTlsClient();
const { clientKeyShareBase64Url } = client.startHandshake();

// Server handles handshake and creates session
const server = new HybridTlsServer();
const { serverKeyShareBase64Url, session: serverSession } = server.handleClientKeyShare(clientKeyShareBase64Url);

// Client completes handshake and creates session
const clientSession = client.completeHandshake(serverKeyShareBase64Url);

// Bidirectional encrypted communication
const record = clientSession.send('Hello Quantum World!');
const plaintext = serverSession.receive(record);
```

## Reality Gate Status

- Production Deployment Status: **LOCKED (0 / 1,000 certified)**
- Local Reality-Gate Verification: **ACTIVE**
