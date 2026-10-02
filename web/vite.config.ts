/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

const mock = process.env.VITE_MOCK === '1';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // The msw service worker script only exists for `npm run dev:mock`, so it
  // never ends up in the production bundle.
  publicDir: mock ? 'mock/public' : false,
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    proxy: mock
      ? undefined
      : {
          '/api': { target: 'http://localhost:8080', changeOrigin: false },
          '/auth': { target: 'http://localhost:8080', changeOrigin: false },
        },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    css: false,
  },
});
