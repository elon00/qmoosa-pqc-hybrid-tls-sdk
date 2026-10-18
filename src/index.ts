/**
 * QMOOSA Post-Quantum Cryptography — Hybrid TLS 1.3 SDK & Secure Session Transport
 *
 * Provides high-level abstractions:
 * - HybridTlsClient: Client handshake initiator and encrypted stream
 * - HybridTlsServer: Server handshake responder and encrypted stream
 * - HybridTlsSession: Bidirectional record transport with sequence number tracking
 * - Wire encoding utilities (Hex, Base64Url)
 */

import {
  X25519_MLKEM_768,
  getHybridGroupParameters,
  constantTimeEqual,
  type HybridGroupParameters,
  type HybridClientKeyShare,
  type HybridServerKeyShare,
  type HybridTlsSessionKeys,
  type EncryptedTlsRecord,
  type TlsRecordHeader
} from '@qmoosa/pqc-hybrid-tls-protocol';
import {
  HybridTlsEngine,
  computeRecordNonce,
  type ClientEphemeralState,
  type ClientInitResult,
  type ServerRespondResult
} from '@qmoosa/pqc-hybrid-tls-engine';

export * from '@qmoosa/pqc-hybrid-tls-protocol';
export * from '@qmoosa/pqc-hybrid-tls-engine';

export function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) {
    throw new Error('INVALID_HEX_STRING: Length must be even');
  }
  return new Uint8Array(Buffer.from(clean, 'hex'));
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

export function base64UrlToBytes(str: string): Uint8Array {
  return new Uint8Array(Buffer.from(str, 'base64url'));
}

export class HybridTlsSession {
  private readonly engine: HybridTlsEngine;
  private readonly keys: HybridTlsSessionKeys;
  private readonly isClient: boolean;
  private sendSeq: bigint = 0n;
  private recvSeq: bigint = 0n;

  constructor(engine: HybridTlsEngine, keys: HybridTlsSessionKeys, isClient: boolean) {
    this.engine = engine;
    this.keys = keys;
    this.isClient = isClient;
  }

  /**
   * Encrypts and formats a message into an EncryptedTlsRecord.
   */
  public send(data: Uint8Array | string): EncryptedTlsRecord {
    const payload = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const writeKey = this.isClient ? this.keys.clientWriteKey : this.keys.serverWriteKey;
    const writeIV = this.isClient ? this.keys.clientWriteIV : this.keys.serverWriteIV;

    const record = this.engine.encryptRecord(payload, writeKey, writeIV, this.sendSeq);
    this.sendSeq += 1n;
    return record;
  }

  /**
   * Decrypts and verifies an EncryptedTlsRecord from the peer.
   */
  public receive(record: EncryptedTlsRecord): Uint8Array {
    const readKey = this.isClient ? this.keys.serverWriteKey : this.keys.clientWriteKey;
    const readIV = this.isClient ? this.keys.serverWriteIV : this.keys.clientWriteIV;

    if (record.sequenceNumber !== this.recvSeq) {
      throw new Error(`SEQUENCE_NUMBER_MISMATCH: Expected ${this.recvSeq}, got ${record.sequenceNumber}`);
    }

    const plaintext = this.engine.decryptRecord(record, readKey, readIV, this.recvSeq);
    this.recvSeq += 1n;
    return plaintext;
  }

  public getSessionKeys(): HybridTlsSessionKeys {
    return this.keys;
  }
}

export class HybridTlsClient {
  private readonly engine: HybridTlsEngine;
  private clientState?: ClientEphemeralState;

  constructor(engine?: HybridTlsEngine) {
    this.engine = engine ?? new HybridTlsEngine();
  }

  /**
   * Starts hybrid handshake and returns serialized ClientKeyShare (raw bytes or base64url).
   */
  public startHandshake(): { clientKeyShare: Uint8Array; clientKeyShareBase64Url: string } {
    const { clientState, clientKeyShare } = this.engine.clientInit();
    this.clientState = clientState;
    return {
      clientKeyShare,
      clientKeyShareBase64Url: bytesToBase64Url(clientKeyShare)
    };
  }

  /**
   * Completes handshake with ServerKeyShare and returns active secure session.
   */
  public completeHandshake(
    serverKeyShare: Uint8Array | string,
    transcriptContext?: Uint8Array
  ): HybridTlsSession {
    if (!this.clientState) {
      throw new Error('HANDSHAKE_STATE_INVALID: Handshake has not been started');
    }
    const serverShareBytes = typeof serverKeyShare === 'string'
      ? (serverKeyShare.startsWith('0x') ? hexToBytes(serverKeyShare) : base64UrlToBytes(serverKeyShare))
      : serverKeyShare;

    const sessionKeys = this.engine.clientComplete(this.clientState, serverShareBytes, transcriptContext);
    this.clientState = undefined; // Zero out ephemeral state

    return new HybridTlsSession(this.engine, sessionKeys, true);
  }
}

export class HybridTlsServer {
  private readonly engine: HybridTlsEngine;

  constructor(engine?: HybridTlsEngine) {
    this.engine = engine ?? new HybridTlsEngine();
  }

  /**
   * Processes ClientKeyShare and returns ServerKeyShare along with active secure session.
   */
  public handleClientKeyShare(
    clientKeyShare: Uint8Array | string,
    transcriptContext?: Uint8Array
  ): {
    serverKeyShare: Uint8Array;
    serverKeyShareBase64Url: string;
    session: HybridTlsSession;
  } {
    const clientShareBytes = typeof clientKeyShare === 'string'
      ? (clientKeyShare.startsWith('0x') ? hexToBytes(clientKeyShare) : base64UrlToBytes(clientKeyShare))
      : clientKeyShare;

    const { serverKeyShare, sessionKeys } = this.engine.serverRespond(clientShareBytes, transcriptContext);
    const session = new HybridTlsSession(this.engine, sessionKeys, false);

    return {
      serverKeyShare,
      serverKeyShareBase64Url: bytesToBase64Url(serverKeyShare),
      session
    };
  }
}
