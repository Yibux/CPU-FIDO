import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    // `npm run dev` poza Dockerem: API musi wtedy działać z ORIGIN=http://localhost:5173.
    proxy: { '/api': 'http://localhost:3000' },
  },
});
