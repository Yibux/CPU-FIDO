import { randomUUID } from 'node:crypto';
import type { Request, Response } from 'express';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import { config } from './config.js';
import {
  getCredential,
  getUserById,
  getUserByUsername,
  isUniqueViolation,
  listCredentials,
  markCredentialUsed,
  saveRegistration,
} from './db.js';

interface PendingChallenge {
  challenge: string;
  expiresAt: number;
}

interface PendingRegistration extends PendingChallenge {
  userId: string;
  username: string;
}

declare module 'express-session' {
  interface SessionData {
    userId?: string;
    registration?: PendingRegistration;
    authentication?: PendingChallenge;
  }
}

const USERNAME_RE = /^[a-z0-9._-]{3,32}$/;

const fail = (res: Response, status: number, error: string, extra: object = {}) =>
  res.status(status).json({ error, ...extra });

const errorMessage = (err: unknown) => (err instanceof Error ? err.message : String(err));

/** Nowe ID sesji po zalogowaniu (ochrona przed session fixation). */
function regenerateSession(req: Request): Promise<void> {
  return new Promise((resolve, reject) =>
    req.session.regenerate((err) => (err ? reject(err) : resolve())),
  );
}

/**
 * Zdejmuje challenge z sesji – jest jednorazowy niezależnie od wyniku weryfikacji,
 * więc ponowne wysłanie tej samej odpowiedzi nie przejdzie.
 */
function takeChallenge<K extends 'registration' | 'authentication'>(
  req: Request,
  res: Response,
  key: K,
) {
  const pending = req.session[key];
  delete req.session[key];
  if (!pending) {
    fail(res, 400, 'Brak aktywnego challenge – rozpocznij ceremonię od nowa.');
    return null;
  }
  if (Date.now() > pending.expiresAt) {
    fail(res, 400, 'Challenge wygasł – spróbuj ponownie.');
    return null;
  }
  return pending;
}

const isResponseJSON = (value: unknown): value is { id: string; response: object } =>
  typeof value === 'object' &&
  value !== null &&
  typeof (value as { id?: unknown }).id === 'string' &&
  typeof (value as { response?: unknown }).response === 'object' &&
  (value as { response?: unknown }).response !== null;

function credentialName(raw: unknown): string {
  const name = typeof raw === 'string' ? raw.trim().slice(0, 60) : '';
  return name || 'Passkey';
}

// POST /api/register/options
export async function registerOptions(req: Request, res: Response) {
  const current = req.session.userId ? await getUserById(req.session.userId) : null;

  let userId: string;
  let username: string;
  if (current) {
    // Zalogowany użytkownik dodaje kolejny passkey do swojego konta.
    ({ id: userId, username } = current);
  } else {
    username = String(req.body?.username ?? '').trim().toLowerCase();
    if (!USERNAME_RE.test(username)) {
      return fail(res, 400, 'Nazwa użytkownika: 3–32 znaki (a–z, 0–9, kropka, myślnik, podkreślenie).');
    }
    if (await getUserByUsername(username)) {
      return fail(res, 409, 'Ta nazwa jest zajęta. Zaloguj się, aby dodać kolejny passkey do konta.');
    }
    userId = randomUUID();
  }

  const existing = current ? await listCredentials(userId) : [];
  const options = await generateRegistrationOptions({
    rpName: config.rpName,
    rpID: config.rpID,
    userName: username,
    userDisplayName: username,
    userID: new TextEncoder().encode(userId),
    attestationType: 'none',
    excludeCredentials: existing.map((c) => ({
      id: c.id,
      transports: c.transports as AuthenticatorTransportFuture[],
    })),
    authenticatorSelection: {
      residentKey: 'required',
      userVerification: 'required',
    },
  });

  req.session.registration = {
    challenge: options.challenge,
    expiresAt: Date.now() + config.challengeTtlMs,
    userId,
    username,
  };
  res.json(options);
}

// POST /api/register/verify
export async function registerVerify(req: Request, res: Response) {
  const pending = takeChallenge(req, res, 'registration');
  if (!pending) return;
  if (!isResponseJSON(req.body?.response)) return fail(res, 400, 'Niepoprawna odpowiedź uwierzytelniacza.');

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: req.body.response as RegistrationResponseJSON,
      expectedChallenge: pending.challenge,
      expectedOrigin: config.origin,
      expectedRPID: config.rpID,
      requireUserVerification: true,
    });
  } catch (err) {
    return fail(res, 400, `Weryfikacja rejestracji nie powiodła się: ${errorMessage(err)}`);
  }
  if (!verification.verified || !verification.registrationInfo) {
    return fail(res, 400, 'Weryfikacja rejestracji nie powiodła się.');
  }

  const { credential, credentialDeviceType, credentialBackedUp, aaguid } =
    verification.registrationInfo;
  try {
    await saveRegistration(
      { id: pending.userId, username: pending.username },
      {
        id: credential.id,
        public_key: Buffer.from(credential.publicKey),
        counter: credential.counter,
        transports: credential.transports ?? [],
        device_type: credentialDeviceType,
        backed_up: credentialBackedUp,
        aaguid: aaguid || null,
        name: credentialName(req.body.name),
      },
    );
  } catch (err) {
    if (isUniqueViolation(err)) {
      return fail(res, 409, 'Ten passkey albo ta nazwa użytkownika są już zarejestrowane.');
    }
    throw err;
  }

  if (req.session.userId !== pending.userId) {
    await regenerateSession(req);
    req.session.userId = pending.userId;
  }
  res.json({ verified: true, user: { id: pending.userId, username: pending.username } });
}

// POST /api/login/options
export async function loginOptions(req: Request, res: Response) {
  // Bez allowCredentials: uwierzytelniacz sam wybiera discoverable credential (logowanie bez loginu, autofill).
  const options = await generateAuthenticationOptions({
    rpID: config.rpID,
    userVerification: 'required',
  });
  req.session.authentication = {
    challenge: options.challenge,
    expiresAt: Date.now() + config.challengeTtlMs,
  };
  res.json(options);
}

// POST /api/login/verify
export async function loginVerify(req: Request, res: Response) {
  const pending = takeChallenge(req, res, 'authentication');
  if (!pending) return;
  if (!isResponseJSON(req.body?.response)) return fail(res, 400, 'Niepoprawna odpowiedź uwierzytelniacza.');
  const response = req.body.response as AuthenticationResponseJSON;

  const credential = await getCredential(response.id);
  const user = credential && (await getUserById(credential.user_id));
  if (!credential || !user) {
    return fail(res, 404, 'Ten passkey nie jest (już) zarejestrowany w serwisie.', {
      unknownCredentialId: response.id,
    });
  }

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: pending.challenge,
      expectedOrigin: config.origin,
      expectedRPID: config.rpID,
      requireUserVerification: true,
      credential: {
        id: credential.id,
        publicKey: new Uint8Array(credential.public_key),
        counter: credential.counter,
        transports: credential.transports as AuthenticatorTransportFuture[],
      },
    });
  } catch (err) {
    return fail(res, 400, `Weryfikacja logowania nie powiodła się: ${errorMessage(err)}`);
  }
  if (!verification.verified) return fail(res, 400, 'Weryfikacja logowania nie powiodła się.');

  const { newCounter, credentialBackedUp } = verification.authenticationInfo;
  await markCredentialUsed(credential.id, newCounter, credentialBackedUp);

  await regenerateSession(req);
  req.session.userId = user.id;
  res.json({ verified: true, user: { id: user.id, username: user.username } });
}
