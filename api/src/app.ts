import connectPgSimple from 'connect-pg-simple';
import express, { type NextFunction, type Request, type Response } from 'express';
import session from 'express-session';
import { config, secureCookies } from './config.js';
import { deleteCredential, getUserById, listCredentials, pool, type User } from './db.js';
import { loginOptions, loginVerify, registerOptions, registerVerify } from './webauthn.js';

const SESSION_COOKIE = 'sid';

type AuthedLocals = { user: User };

async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const user = req.session.userId ? await getUserById(req.session.userId) : null;
  if (!user) return res.status(401).json({ error: 'Nie jesteś zalogowany.' });
  res.locals.user = user;
  next();
}

export function createApp() {
  const app = express();
  app.disable('x-powered-by');
  // Jedyny hop przed API to nginx, który ustawia X-Forwarded-Proto (potrzebne dla cookie Secure za tunelem).
  app.set('trust proxy', 1);
  app.use(express.json({ limit: '100kb' }));

  const api = express.Router();

  // Przed middleware sesji, żeby healthcheck nie dotykał tabeli session.
  api.get('/healthz', async (_req, res) => {
    try {
      await pool.query('SELECT 1');
      res.json({ status: 'ok', rpID: config.rpID, origin: config.origin });
    } catch {
      res.status(503).json({ status: 'error', error: 'Baza danych niedostępna.' });
    }
  });

  const PgStore = connectPgSimple(session);
  api.use(
    session({
      store: new PgStore({ pool, tableName: 'session' }),
      name: SESSION_COOKIE,
      secret: config.sessionSecret,
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: secureCookies,
        maxAge: 7 * 24 * 60 * 60 * 1000,
      },
    }),
  );

  api.post('/register/options', registerOptions);
  api.post('/register/verify', registerVerify);
  api.post('/login/options', loginOptions);
  api.post('/login/verify', loginVerify);

  api.get('/me', requireAuth, (_req, res: Response<unknown, AuthedLocals>) => {
    const { id, username } = res.locals.user;
    res.json({ user: { id, username } });
  });

  api.post('/logout', (req, res, next) => {
    req.session.destroy((err) => {
      if (err) return next(err);
      res.clearCookie(SESSION_COOKIE);
      res.status(204).end();
    });
  });

  api.get('/credentials', requireAuth, async (_req, res: Response<unknown, AuthedLocals>) => {
    const credentials = await listCredentials(res.locals.user.id);
    res.json({
      credentials: credentials.map((c) => ({
        id: c.id,
        name: c.name,
        deviceType: c.device_type,
        backedUp: c.backed_up,
        transports: c.transports,
        aaguid: c.aaguid,
        counter: c.counter,
        createdAt: c.created_at,
        lastUsedAt: c.last_used_at,
      })),
    });
  });

  api.delete(
    '/credentials/:id',
    requireAuth,
    async (req: Request<{ id: string }>, res: Response<unknown, AuthedLocals>) => {
      const result = await deleteCredential(res.locals.user.id, req.params.id);
      if (result === 'not_found') return res.status(404).json({ error: 'Nie ma takiego passkey.' });
      if (result === 'last_one') {
        return res
          .status(409)
          .json({ error: 'Nie można usunąć ostatniego passkey – konto zostałoby bez możliwości logowania.' });
      }
      res.status(204).end();
    },
  );

  app.use('/api', api);
  app.use((_req, res) => {
    res.status(404).json({ error: 'Nie znaleziono.' });
  });
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const status = (err as { status?: number }).status;
    if (status && status >= 400 && status < 500) {
      return res.status(status).json({ error: 'Niepoprawne żądanie.' });
    }
    console.error('[api] nieobsłużony błąd:', err);
    res.status(500).json({ error: 'Błąd serwera.' });
  });

  return app;
}
