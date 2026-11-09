const env = (name: string, fallback: string): string => process.env[name]?.trim() || fallback;

export const config = {
  port: Number(env('PORT', '3000')),
  /** RP ID: sama domena (bez schematu i portu). Passkeys są do niej trwale przypisane. */
  rpID: env('RP_ID', 'localhost'),
  rpName: env('RP_NAME', 'FIDO2 Passkeys Demo'),
  /** Pełny origin, pod którym przeglądarka widzi aplikację. */
  origin: env('ORIGIN', 'http://localhost:8080').replace(/\/+$/, ''),
  sessionSecret: env('SESSION_SECRET', 'dev-only-secret-change-me'),
  databaseUrl: env('DATABASE_URL', 'postgres://fido:fido@localhost:5432/fido'),
  /** Czas ważności challenge (ms). */
  challengeTtlMs: Number(env('CHALLENGE_TTL_MS', '300000')),
};

export const secureCookies = config.origin.startsWith('https://');

/** Zwraca opis problemu, jeśli ORIGIN nie pasuje do RP_ID (częsty błąd przy zmianie adresu tunelu). */
export function configProblem(): string | null {
  let host: string;
  try {
    host = new URL(config.origin).hostname;
  } catch {
    return `ORIGIN "${config.origin}" nie jest poprawnym adresem URL`;
  }
  if (host !== config.rpID && !host.endsWith(`.${config.rpID}`)) {
    return `host z ORIGIN (${host}) nie należy do RP_ID (${config.rpID}) – przeglądarka odrzuci ceremonie WebAuthn`;
  }
  return null;
}
