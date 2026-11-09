import { createApp } from './app.js';
import { config, configProblem } from './config.js';
import { migrate, pool, waitForDb } from './db.js';

await waitForDb();
await migrate();

const problem = configProblem();
if (problem) console.warn(`[api] UWAGA: ${problem}`);
if (config.sessionSecret === 'dev-only-secret-change-me') {
  console.warn('[api] UWAGA: używany jest domyślny SESSION_SECRET – ustaw własny w .env');
}

const server = createApp().listen(config.port, () => {
  console.log(`[api] port ${config.port}, RP_ID=${config.rpID}, ORIGIN=${config.origin}`);
});

for (const signal of ['SIGTERM', 'SIGINT'] as const) {
  process.on(signal, () => {
    server.close(() => {
      void pool.end().finally(() => process.exit(0));
    });
  });
}
