import request from 'supertest';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createApp } from '../src/app.js';
import { config } from '../src/config.js';
import { migrate, pool } from '../src/db.js';
import { SoftAuthenticator } from './softAuthenticator.js';

const app = createApp();
type Agent = ReturnType<typeof request.agent>;

const newAuthenticator = (synced = true) => new SoftAuthenticator(config.rpID, config.origin, synced);

async function register(agent: Agent, authenticator: SoftAuthenticator, username?: string, name?: string) {
  const options = await agent.post('/api/register/options').send({ username });
  expect(options.status).toBe(200);
  return agent
    .post('/api/register/verify')
    .send({ response: authenticator.create(options.body), name });
}

async function login(agent: Agent, authenticator: SoftAuthenticator, credentialId?: string) {
  const options = await agent.post('/api/login/options').send();
  expect(options.status).toBe(200);
  return agent
    .post('/api/login/verify')
    .send({ response: authenticator.get(options.body, { credentialId }) });
}

beforeAll(async () => {
  await migrate();
});

beforeEach(async () => {
  await pool.query('TRUNCATE users, credentials, "session" CASCADE');
});

afterEach(() => {
  vi.restoreAllMocks();
});

afterAll(async () => {
  await pool.end();
});

describe('healthz i ochrona endpointów', () => {
  it('GET /api/healthz zwraca ok', async () => {
    const res = await request(app).get('/api/healthz');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: 'ok', rpID: config.rpID });
  });

  it('bez sesji /me, /credentials i DELETE zwracają 401', async () => {
    expect((await request(app).get('/api/me')).status).toBe(401);
    expect((await request(app).get('/api/credentials')).status).toBe(401);
    expect((await request(app).delete('/api/credentials/abc')).status).toBe(401);
  });
});

describe('rejestracja (T1, T3)', () => {
  it('opcje wymagają discoverable credential i weryfikacji użytkownika', async () => {
    const res = await request(app).post('/api/register/options').send({ username: 'alice' });
    expect(res.status).toBe(200);
    expect(res.body.rp).toMatchObject({ id: config.rpID });
    expect(res.body.attestation).toBe('none');
    expect(res.body.authenticatorSelection).toMatchObject({
      residentKey: 'required',
      userVerification: 'required',
    });
    expect(res.body.excludeCredentials).toEqual([]);
  });

  it('tworzy użytkownika, zapisuje passkey i loguje', async () => {
    const agent = request.agent(app);
    const authenticator = newAuthenticator();
    const res = await register(agent, authenticator, 'Alice', 'Windows Hello');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ verified: true, user: { username: 'alice' } });

    const me = await agent.get('/api/me');
    expect(me.body.user.username).toBe('alice');

    const { rows } = await pool.query('SELECT * FROM credentials');
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      id: authenticator.credentialIds[0],
      user_id: me.body.user.id,
      counter: 1,
      transports: ['internal'],
      device_type: 'multiDevice',
      backed_up: true,
      name: 'Windows Hello',
      last_used_at: null,
    });
    // Serwer przechowuje wyłącznie klucz publiczny (COSE).
    expect(Buffer.isBuffer(rows[0].public_key)).toBe(true);
  });

  it('passkey przypisany do urządzenia ma backed_up = false', async () => {
    const agent = request.agent(app);
    await register(agent, newAuthenticator(false), 'bob');
    const list = await agent.get('/api/credentials');
    expect(list.body.credentials[0]).toMatchObject({ deviceType: 'singleDevice', backedUp: false });
  });

  it('odrzuca niepoprawną i zajętą nazwę użytkownika', async () => {
    expect((await request(app).post('/api/register/options').send({ username: 'a' })).status).toBe(400);
    expect((await request(app).post('/api/register/options').send({})).status).toBe(400);

    await register(request.agent(app), newAuthenticator(), 'alice');
    const taken = await request(app).post('/api/register/options').send({ username: 'ALICE' });
    expect(taken.status).toBe(409);
  });
});

describe('logowanie (T2)', () => {
  it('loguje bez podawania loginu i aktualizuje counter oraz last_used_at', async () => {
    const authenticator = newAuthenticator();
    await register(request.agent(app), authenticator, 'alice');

    const agent = request.agent(app);
    const options = await agent.post('/api/login/options').send();
    expect(options.body.allowCredentials ?? []).toEqual([]);
    expect(options.body.userVerification).toBe('required');

    const res = await agent.post('/api/login/verify').send({ response: authenticator.get(options.body) });
    expect(res.status).toBe(200);
    expect(res.body.user.username).toBe('alice');
    expect((await agent.get('/api/me')).status).toBe(200);

    const { rows } = await pool.query('SELECT counter, last_used_at FROM credentials');
    expect(rows[0].counter).toBe(2);
    expect(rows[0].last_used_at).toBeInstanceOf(Date);
  });

  it('wylogowanie kończy sesję', async () => {
    const agent = request.agent(app);
    await register(agent, newAuthenticator(), 'alice');
    expect((await agent.post('/api/logout')).status).toBe(204);
    expect((await agent.get('/api/me')).status).toBe(401);
  });

  it('odrzuca nieznany passkey', async () => {
    const stranger = newAuthenticator();
    stranger.create((await request(app).post('/api/register/options').send({ username: 'ghost' })).body);
    const res = await login(request.agent(app), stranger);
    expect(res.status).toBe(404);
    expect(res.body.unknownCredentialId).toBe(stranger.credentialIds[0]);
  });

  it('odrzuca cofnięty licznik podpisów (sklonowany uwierzytelniacz)', async () => {
    const authenticator = newAuthenticator();
    await register(request.agent(app), authenticator, 'alice');
    expect((await login(request.agent(app), authenticator)).status).toBe(200); // counter = 2

    const agent = request.agent(app);
    const options = await agent.post('/api/login/options').send();
    const res = await agent
      .post('/api/login/verify')
      .send({ response: authenticator.get(options.body, { signCount: 1 }) });
    expect(res.status).toBe(400);
    expect((await agent.get('/api/me')).status).toBe(401);
  });
});

describe('scenariusze negatywne (T7)', () => {
  it('rejestracja ze złego originu jest odrzucana', async () => {
    const agent = request.agent(app);
    const options = await agent.post('/api/register/options').send({ username: 'alice' });
    const response = newAuthenticator().create(options.body, { origin: 'https://evil.example' });
    const res = await agent.post('/api/register/verify').send({ response });
    expect(res.status).toBe(400);
    expect((await pool.query('SELECT 1 FROM users')).rowCount).toBe(0);
  });

  it('logowanie ze złego originu (phishing) jest odrzucane', async () => {
    const authenticator = newAuthenticator();
    await register(request.agent(app), authenticator, 'alice');

    const agent = request.agent(app);
    const options = await agent.post('/api/login/options').send();
    const response = authenticator.get(options.body, { origin: 'https://evil.example' });
    const res = await agent.post('/api/login/verify').send({ response });
    expect(res.status).toBe(400);
    expect((await agent.get('/api/me')).status).toBe(401);
  });

  it('challenge jest jednorazowy – powtórzona odpowiedź nie przechodzi', async () => {
    const authenticator = newAuthenticator();
    await register(request.agent(app), authenticator, 'alice');

    const agent = request.agent(app);
    const options = await agent.post('/api/login/options').send();
    const response = authenticator.get(options.body);
    expect((await agent.post('/api/login/verify').send({ response })).status).toBe(200);
    const replay = await agent.post('/api/login/verify').send({ response });
    expect(replay.status).toBe(400);
    expect(replay.body.error).toMatch(/Brak aktywnego challenge/);
  });

  it('przechwycona asercja nie pasuje do nowego challenge', async () => {
    const authenticator = newAuthenticator();
    await register(request.agent(app), authenticator, 'alice');

    const victim = request.agent(app);
    const captured = authenticator.get((await victim.post('/api/login/options').send()).body);

    const attacker = request.agent(app);
    await attacker.post('/api/login/options').send();
    const res = await attacker.post('/api/login/verify').send({ response: captured });
    expect(res.status).toBe(400);
    expect((await attacker.get('/api/me')).status).toBe(401);
  });

  it('weryfikacja bez wcześniejszego challenge jest odrzucana', async () => {
    const authenticator = newAuthenticator();
    await register(request.agent(app), authenticator, 'alice');
    const foreign = authenticator.get((await request.agent(app).post('/api/login/options').send()).body);
    const res = await request(app).post('/api/login/verify').send({ response: foreign });
    expect(res.status).toBe(400);
  });

  it('wygasły challenge jest odrzucany (rejestracja i logowanie)', async () => {
    const authenticator = newAuthenticator();
    await register(request.agent(app), authenticator, 'alice');
    const realNow = Date.now;

    const loginAgent = request.agent(app);
    const loginOpts = await loginAgent.post('/api/login/options').send();
    const regAgent = request.agent(app);
    const regOpts = await regAgent.post('/api/register/options').send({ username: 'bob' });

    vi.spyOn(Date, 'now').mockImplementation(() => realNow() + config.challengeTtlMs + 1000);

    const loginRes = await loginAgent
      .post('/api/login/verify')
      .send({ response: authenticator.get(loginOpts.body) });
    expect(loginRes.status).toBe(400);
    expect(loginRes.body.error).toMatch(/wygasł/);

    const regRes = await regAgent
      .post('/api/register/verify')
      .send({ response: newAuthenticator().create(regOpts.body) });
    expect(regRes.status).toBe(400);
    expect(regRes.body.error).toMatch(/wygasł/);
  });

  it('zniekształcone body jest odrzucane', async () => {
    const agent = request.agent(app);
    await agent.post('/api/login/options').send();
    expect((await agent.post('/api/login/verify').send({ response: 'x' })).status).toBe(400);
    const raw = await request(app)
      .post('/api/login/verify')
      .set('Content-Type', 'application/json')
      .send('{nie-json');
    expect(raw.status).toBe(400);
  });
});

describe('wiele passkeys (T6, T8)', () => {
  it('excludeCredentials blokuje ponowną rejestrację tego samego urządzenia (T8)', async () => {
    const agent = request.agent(app);
    const authenticator = newAuthenticator();
    await register(agent, authenticator, 'alice');

    const options = await agent.post('/api/register/options').send();
    expect(options.body.user.name).toBe('alice');
    expect(options.body.excludeCredentials.map((c: { id: string }) => c.id)).toEqual(
      authenticator.credentialIds,
    );
    expect(() => authenticator.create(options.body)).toThrowError(
      expect.objectContaining({ name: 'InvalidStateError' }),
    );
  });

  it('usunięty passkey przestaje działać, pozostały działa dalej (T6)', async () => {
    const agent = request.agent(app);
    const laptop = newAuthenticator(false);
    const phone = newAuthenticator();
    await register(agent, laptop, 'alice', 'Laptop');
    expect((await register(agent, phone, undefined, 'Telefon')).status).toBe(200);

    const list = await agent.get('/api/credentials');
    expect(list.body.credentials.map((c: { name: string }) => c.name)).toEqual(['Laptop', 'Telefon']);
    expect(list.body.credentials[0]).not.toHaveProperty('publicKey');

    const del = await agent.delete(`/api/credentials/${laptop.credentialIds[0]}`);
    expect(del.status).toBe(204);

    expect((await login(request.agent(app), laptop)).status).toBe(404);
    expect((await login(request.agent(app), phone)).status).toBe(200);
  });

  it('nie pozwala usunąć ostatniego ani cudzego passkey', async () => {
    const alice = request.agent(app);
    const aliceKey = newAuthenticator();
    await register(alice, aliceKey, 'alice');
    const bob = request.agent(app);
    const bobKey = newAuthenticator();
    await register(bob, bobKey, 'bob');

    expect((await alice.delete(`/api/credentials/${aliceKey.credentialIds[0]}`)).status).toBe(409);
    expect((await alice.delete(`/api/credentials/${bobKey.credentialIds[0]}`)).status).toBe(404);
    expect((await pool.query('SELECT 1 FROM credentials')).rowCount).toBe(2);
  });
});

describe('trwałość sesji (T9)', () => {
  it('sesja z bazy działa w nowej instancji aplikacji (restart kontenera api)', async () => {
    const registered = await register(request.agent(app), newAuthenticator(), 'alice');
    const setCookie = registered.headers['set-cookie'] as unknown as string[];
    const cookie = setCookie[0].split(';')[0];
    expect(setCookie[0]).toMatch(/HttpOnly/i);
    expect(setCookie[0]).toMatch(/SameSite=Lax/i);

    const restarted = createApp();
    const me = await request(restarted).get('/api/me').set('Cookie', cookie);
    expect(me.status).toBe(200);
    expect(me.body.user.username).toBe('alice');
  });
});
