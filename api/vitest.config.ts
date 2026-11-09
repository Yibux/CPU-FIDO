import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    globalSetup: ['test/globalSetup.ts'],
    // Wszystkie pliki testowe dzielą jedną bazę, więc nie mogą iść równolegle.
    fileParallelism: false,
    env: {
      RP_ID: process.env.RP_ID ?? 'localhost',
      ORIGIN: process.env.ORIGIN ?? 'http://localhost:8080',
      SESSION_SECRET: process.env.SESSION_SECRET ?? 'test-secret',
      DATABASE_URL: process.env.DATABASE_URL ?? 'postgres://fido:fido@localhost:5432/fido_test',
    },
  },
});
