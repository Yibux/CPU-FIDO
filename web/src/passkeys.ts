import {
  browserSupportsWebAuthn,
  browserSupportsWebAuthnAutofill,
  platformAuthenticatorIsAvailable,
  startAuthentication,
  startRegistration,
  WebAuthnAbortService,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/browser';

export interface User {
  id: string;
  username: string;
}

export interface Passkey {
  id: string;
  name: string;
  deviceType: 'singleDevice' | 'multiDevice';
  backedUp: boolean;
  transports: string[];
  aaguid: string | null;
  counter: number;
  createdAt: string;
  lastUsedAt: string | null;
}

export interface ServerInfo {
  rpID: string;
  origin: string;
}

export interface Support {
  webauthn: boolean;
  /** isUserVerifyingPlatformAuthenticatorAvailable() */
  platform: boolean;
  /** isConditionalMediationAvailable() */
  autofill: boolean;
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly data: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

async function api<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`/api${path}`, {
    method,
    credentials: 'same-origin',
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 204) return undefined as T;
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(res.status, data?.error ?? `Błąd serwera (${res.status})`, data ?? {});
  return data as T;
}

export async function detectSupport(): Promise<Support> {
  const webauthn = browserSupportsWebAuthn();
  if (!webauthn) return { webauthn, platform: false, autofill: false };
  const [platform, autofill] = await Promise.all([
    platformAuthenticatorIsAvailable().catch(() => false),
    browserSupportsWebAuthnAutofill().catch(() => false),
  ]);
  return { webauthn, platform, autofill };
}

export const getServerInfo = () => api<ServerInfo>('GET', '/healthz');

export async function getMe(): Promise<User | null> {
  try {
    return (await api<{ user: User }>('GET', '/me')).user;
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) return null;
    throw err;
  }
}

/** Rejestracja passkey: nowe konto (username) albo kolejny passkey zalogowanego użytkownika. */
export async function registerPasskey(username?: string): Promise<User> {
  const optionsJSON = await api<PublicKeyCredentialCreationOptionsJSON>('POST', '/register/options', {
    username,
  });
  const response = await startRegistration({ optionsJSON });
  const result = await api<{ user: User }>('POST', '/register/verify', {
    response,
    name: guessDeviceName(response.authenticatorAttachment),
  });
  return result.user;
}

/**
 * Logowanie passkeyem bez podawania loginu.
 * autofill = true uruchamia conditional UI: żądanie czeka w tle, aż użytkownik wybierze passkey z podpowiedzi pola.
 */
export async function loginWithPasskey({ autofill = false } = {}): Promise<User> {
  const optionsJSON = await api<PublicKeyCredentialRequestOptionsJSON>('POST', '/login/options');
  const response = await startAuthentication({ optionsJSON, useBrowserAutofill: autofill });
  try {
    return (await api<{ user: User }>('POST', '/login/verify', { response })).user;
  } catch (err) {
    if (err instanceof ApiError && typeof err.data.unknownCredentialId === 'string') {
      void signalUnknownCredential(optionsJSON.rpId, err.data.unknownCredentialId);
    }
    throw err;
  }
}

/** Podpowiada menedżerowi haseł, że serwer nie zna już tego passkey (może go ukryć/usunąć). */
async function signalUnknownCredential(rpId: string | undefined, credentialId: string) {
  const signal = (
    PublicKeyCredential as unknown as {
      signalUnknownCredential?: (o: { rpId: string; credentialId: string }) => Promise<void>;
    }
  ).signalUnknownCredential;
  if (!rpId || !signal) return;
  await signal.call(PublicKeyCredential, { rpId, credentialId }).catch(() => {});
}

export const cancelPendingCeremony = () => WebAuthnAbortService.cancelCeremony();

export const logout = () => api<void>('POST', '/logout');

export const listPasskeys = async () =>
  (await api<{ credentials: Passkey[] }>('GET', '/credentials')).credentials;

export const deletePasskey = (id: string) =>
  api<void>('DELETE', `/credentials/${encodeURIComponent(id)}`);

export const isAbort = (err: unknown) => err instanceof Error && err.name === 'AbortError';

/** Czytelny komunikat dla błędów ceremonii WebAuthn i błędów API. */
export function describeError(err: unknown, ceremony: 'register' | 'login'): string {
  if (err instanceof ApiError) return err.message;
  if (!(err instanceof Error)) return 'Nieznany błąd.';
  switch (err.name) {
    case 'NotAllowedError':
      return ceremony === 'register'
        ? 'Rejestracja została anulowana albo upłynął czas na potwierdzenie.'
        : 'Logowanie zostało anulowane, upłynął czas albo na tym urządzeniu nie ma passkey dla tego serwisu.';
    case 'InvalidStateError':
      return 'To urządzenie ma już passkey przypisany do tego konta – nie trzeba rejestrować go ponownie.';
    case 'SecurityError':
      return 'Przeglądarka odrzuciła żądanie: adres strony nie pasuje do RP ID albo strona nie działa przez HTTPS.';
    case 'NotSupportedError':
      return 'To urządzenie nie obsługuje wymaganego typu passkey (klucz rezydentny z weryfikacją użytkownika).';
    default:
      return `Błąd WebAuthn (${err.name}): ${err.message}`;
  }
}

function guessDeviceName(attachment?: string | null): string {
  const ua = navigator.userAgent;
  const os = /Windows/.test(ua)
    ? 'Windows'
    : /Android/.test(ua)
      ? 'Android'
      : /iPhone|iPad|iPod/.test(ua)
        ? 'iOS'
        : /Mac OS X/.test(ua)
          ? 'macOS'
          : /Linux/.test(ua)
            ? 'Linux'
            : 'Nieznany system';
  const browser = /Edg\//.test(ua)
    ? 'Edge'
    : /Firefox\//.test(ua)
      ? 'Firefox'
      : /Chrome\//.test(ua)
        ? 'Chrome'
        : /Safari\//.test(ua)
          ? 'Safari'
          : 'przeglądarka';
  // cross-platform = passkey utworzony na innym urządzeniu (np. telefon przez QR) lub na kluczu sprzętowym.
  return attachment === 'cross-platform'
    ? `Urządzenie zewnętrzne (dodane z ${os} · ${browser})`
    : `${os} · ${browser}`;
}
