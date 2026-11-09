/**
 * Programowy uwierzytelniacz WebAuthn do testów (odpowiednik wirtualnego uwierzytelniacza z DevTools):
 * generuje klucze ES256, buduje attestationObject (fmt "none") i podpisuje asercje.
 */
import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/server';

const b64u = (data: Uint8Array) => Buffer.from(data).toString('base64url');
const sha256 = (data: Uint8Array | string) => createHash('sha256').update(data).digest();

// --- minimalny koder CBOR (inty, bajty, stringi, mapy) ---
type Cbor = number | string | Buffer | Map<number | string, Cbor>;

function head(major: number, n: number): Buffer {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 0x100) return Buffer.from([(major << 5) | 24, n]);
  return Buffer.from([(major << 5) | 25, n >> 8, n & 0xff]);
}

function cbor(value: Cbor): Buffer {
  if (typeof value === 'number') return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === 'string') {
    const bytes = Buffer.from(value, 'utf8');
    return Buffer.concat([head(3, bytes.length), bytes]);
  }
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);
  const parts = [head(5, value.size)];
  for (const [k, v] of value) parts.push(cbor(k), cbor(v));
  return Buffer.concat(parts);
}

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_BE = 0x08;
const FLAG_BS = 0x10;
const FLAG_AT = 0x40;

interface StoredKey {
  privateKey: KeyObject;
  userHandle: string;
  signCount: number;
}

export interface CeremonyOverrides {
  /** Origin wpisany do clientDataJSON (domyślnie poprawny). */
  origin?: string;
  /** Wymuszona wartość licznika podpisów. */
  signCount?: number;
}

export class SoftAuthenticator {
  private keys = new Map<string, StoredKey>();

  constructor(
    private readonly rpId: string,
    private readonly origin: string,
    /** true = passkey synchronizowany (flagi BE+BS), false = przypisany do urządzenia. */
    private readonly synced = true,
  ) {}

  get credentialIds(): string[] {
    return [...this.keys.keys()];
  }

  private flags(extra = 0): number {
    return FLAG_UP | FLAG_UV | (this.synced ? FLAG_BE | FLAG_BS : 0) | extra;
  }

  private authData(flags: number, signCount: number, attested?: Buffer): Buffer {
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(signCount);
    return Buffer.concat([sha256(this.rpId), Buffer.from([flags]), counter, attested ?? Buffer.alloc(0)]);
  }

  private clientData(type: string, challenge: string, origin?: string): Buffer {
    return Buffer.from(
      JSON.stringify({ type, challenge, origin: origin ?? this.origin, crossOrigin: false }),
    );
  }

  /** Odpowiednik navigator.credentials.create(). */
  create(
    options: PublicKeyCredentialCreationOptionsJSON,
    overrides: CeremonyOverrides = {},
  ): RegistrationResponseJSON {
    if (options.excludeCredentials?.some((c) => this.keys.has(c.id))) {
      // Tak zachowuje się prawdziwy uwierzytelniacz (T8).
      throw new DOMException('Credential already registered', 'InvalidStateError');
    }
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' });
    const credentialId = randomBytes(32);
    const id = b64u(credentialId);
    const signCount = overrides.signCount ?? 1;
    this.keys.set(id, { privateKey, userHandle: options.user.id, signCount });

    const coseKey = cbor(
      new Map<number, Cbor>([
        [1, 2], // kty: EC2
        [3, -7], // alg: ES256
        [-1, 1], // crv: P-256
        [-2, Buffer.from(jwk.x!, 'base64url')],
        [-3, Buffer.from(jwk.y!, 'base64url')],
      ]),
    );
    const idLength = Buffer.alloc(2);
    idLength.writeUInt16BE(credentialId.length);
    const attested = Buffer.concat([Buffer.alloc(16), idLength, credentialId, coseKey]);
    const attestationObject = cbor(
      new Map<string, Cbor>([
        ['fmt', 'none'],
        ['attStmt', new Map()],
        ['authData', this.authData(this.flags(FLAG_AT), signCount, attested)],
      ]),
    );

    return {
      id,
      rawId: id,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64u(this.clientData('webauthn.create', options.challenge, overrides.origin)),
        attestationObject: b64u(attestationObject),
        transports: ['internal'],
      },
    };
  }

  /** Odpowiednik navigator.credentials.get() dla discoverable credential. */
  get(
    options: PublicKeyCredentialRequestOptionsJSON,
    overrides: CeremonyOverrides & { credentialId?: string } = {},
  ): AuthenticationResponseJSON {
    const id = overrides.credentialId ?? this.credentialIds[0];
    const key = this.keys.get(id);
    if (!key) throw new DOMException('No credential', 'NotAllowedError');
    key.signCount = overrides.signCount ?? key.signCount + 1;

    const authenticatorData = this.authData(this.flags(), key.signCount);
    const clientDataJSON = this.clientData('webauthn.get', options.challenge, overrides.origin);
    const signature = sign(
      'sha256',
      Buffer.concat([authenticatorData, sha256(clientDataJSON)]),
      key.privateKey,
    );

    return {
      id,
      rawId: id,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64u(clientDataJSON),
        authenticatorData: b64u(authenticatorData),
        signature: b64u(signature),
        userHandle: key.userHandle,
      },
    };
  }
}
