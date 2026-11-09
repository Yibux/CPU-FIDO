import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { config } from './config.js';

// bigint (counter) jako number – liczniki podpisów mieszczą się w 32 bitach.
pg.types.setTypeParser(20, Number);

export const pool = new pg.Pool({ connectionString: config.databaseUrl });

// Zerwane połączenie bezczynnego klienta (np. restart kontenera db) nie może wywracać procesu –
// pula sama otworzy nowe połączenie przy następnym zapytaniu.
pool.on('error', (err) => console.warn(`[db] utracono połączenie: ${err.message}`));

/** Czeka na bazę przy starcie (db może wstawać równolegle, np. po `docker compose restart`). */
export async function waitForDb(attempts = 30, delayMs = 1000): Promise<void> {
  for (let i = 1; ; i++) {
    try {
      await pool.query('SELECT 1');
      return;
    } catch (err) {
      if (i >= attempts) throw err;
      console.log(`[db] baza jeszcze niedostępna, próba ${i}/${attempts}`);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
}

const migrationsDir = fileURLToPath(new URL('../migrations', import.meta.url));
const MIGRATION_LOCK = 727001;

/** Uruchamia brakujące migracje z katalogu migrations/ (każda w transakcji). */
export async function migrate(): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query('SELECT pg_advisory_lock($1)', [MIGRATION_LOCK]);
    await client.query(
      `CREATE TABLE IF NOT EXISTS schema_migrations (
         name text PRIMARY KEY,
         applied_at timestamptz NOT NULL DEFAULT now()
       )`,
    );
    const files = (await readdir(migrationsDir)).filter((f) => f.endsWith('.sql')).sort();
    for (const file of files) {
      const done = await client.query('SELECT 1 FROM schema_migrations WHERE name = $1', [file]);
      if (done.rowCount) continue;
      const sql = await readFile(path.join(migrationsDir, file), 'utf8');
      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations (name) VALUES ($1)', [file]);
        await client.query('COMMIT');
        console.log(`[db] migracja ${file} zastosowana`);
      } catch (err) {
        await client.query('ROLLBACK');
        throw err;
      }
    }
  } finally {
    await client.query('SELECT pg_advisory_unlock($1)', [MIGRATION_LOCK]).catch(() => {});
    client.release();
  }
}

export interface User {
  id: string;
  username: string;
  created_at: Date;
}

export interface Credential {
  id: string;
  user_id: string;
  public_key: Buffer;
  counter: number;
  transports: string[];
  device_type: string;
  backed_up: boolean;
  aaguid: string | null;
  name: string;
  created_at: Date;
  last_used_at: Date | null;
}

export type NewCredential = Pick<
  Credential,
  'id' | 'public_key' | 'counter' | 'transports' | 'device_type' | 'backed_up' | 'aaguid' | 'name'
>;

export const isUniqueViolation = (err: unknown): boolean =>
  typeof err === 'object' && err !== null && (err as { code?: string }).code === '23505';

export async function getUserById(id: string): Promise<User | null> {
  const { rows } = await pool.query<User>('SELECT * FROM users WHERE id = $1', [id]);
  return rows[0] ?? null;
}

export async function getUserByUsername(username: string): Promise<User | null> {
  const { rows } = await pool.query<User>('SELECT * FROM users WHERE username = $1', [username]);
  return rows[0] ?? null;
}

/** Zapisuje passkey; jeśli to pierwsza rejestracja, w tej samej transakcji tworzy użytkownika. */
export async function saveRegistration(
  user: { id: string; username: string },
  cred: NewCredential,
): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      'INSERT INTO users (id, username) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING',
      [user.id, user.username],
    );
    await client.query(
      `INSERT INTO credentials
         (id, user_id, public_key, counter, transports, device_type, backed_up, aaguid, name)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        cred.id,
        user.id,
        cred.public_key,
        cred.counter,
        cred.transports,
        cred.device_type,
        cred.backed_up,
        cred.aaguid,
        cred.name,
      ],
    );
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

export async function getCredential(id: string): Promise<Credential | null> {
  const { rows } = await pool.query<Credential>('SELECT * FROM credentials WHERE id = $1', [id]);
  return rows[0] ?? null;
}

export async function listCredentials(userId: string): Promise<Credential[]> {
  const { rows } = await pool.query<Credential>(
    'SELECT * FROM credentials WHERE user_id = $1 ORDER BY created_at, id',
    [userId],
  );
  return rows;
}

export async function markCredentialUsed(
  id: string,
  counter: number,
  backedUp: boolean,
): Promise<void> {
  await pool.query(
    'UPDATE credentials SET counter = $2, backed_up = $3, last_used_at = now() WHERE id = $1',
    [id, counter, backedUp],
  );
}

/** Usuwa passkey użytkownika, ale nigdy ostatni (konto zostałoby bez możliwości logowania). */
export async function deleteCredential(
  userId: string,
  id: string,
): Promise<'deleted' | 'not_found' | 'last_one'> {
  const del = await pool.query(
    `DELETE FROM credentials
      WHERE id = $1 AND user_id = $2
        AND (SELECT count(*) FROM credentials WHERE user_id = $2) > 1`,
    [id, userId],
  );
  if (del.rowCount) return 'deleted';
  const cred = await getCredential(id);
  return cred && cred.user_id === userId ? 'last_one' : 'not_found';
}
