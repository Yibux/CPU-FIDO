import pg from 'pg';

/** Tworzy testową bazę (nazwa z DATABASE_URL), jeśli jeszcze nie istnieje. */
export default async function setup() {
  const url = new URL(
    process.env.DATABASE_URL ?? 'postgres://fido:fido@localhost:5432/fido_test',
  );
  const dbName = decodeURIComponent(url.pathname.slice(1));
  if (!/^[a-z0-9_]+$/i.test(dbName) || !dbName.endsWith('_test')) {
    throw new Error(`Testy wymagają bazy o nazwie kończącej się na _test (jest: "${dbName}")`);
  }
  url.pathname = '/postgres';
  const client = new pg.Client({ connectionString: url.toString() });
  await client.connect();
  try {
    const exists = await client.query('SELECT 1 FROM pg_database WHERE datname = $1', [dbName]);
    if (!exists.rowCount) await client.query(`CREATE DATABASE "${dbName}"`);
  } finally {
    await client.end();
  }
}
