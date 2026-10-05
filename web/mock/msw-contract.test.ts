import { execFileSync } from 'node:child_process';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { setupServer } from 'msw/node';
import ts from 'typescript';

const require = createRequire(import.meta.url);
const webRoot = dirname(dirname(fileURLToPath(import.meta.url)));

afterEach(() => vi.restoreAllMocks());

describe('MSW integration contract', () => {
  it('keeps development mocks quiet and bypasses unhandled network frames', async () => {
    // MSW's browser entrypoint cannot resolve under Node conditions. Execute
    // the actual wrapper with only its two browser dependencies replaced.
    const source = await readFile(join(webRoot, 'mock/browser.ts'), 'utf8');
    const { outputText } = ts.transpileModule(source, {
      compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
    });
    const start = vi.fn().mockResolvedValue(undefined);
    const exports: { startMock?: () => Promise<void> } = {};
    runInNewContext(outputText, {
      exports,
      require: (specifier: string) => {
        if (specifier === 'msw/browser') return { setupWorker: () => ({ start }) };
        if (specifier === './handlers') return { makeHandlers: () => [] };
        throw new Error(`unexpected browser dependency: ${specifier}`);
      },
    });
    expect(exports.startMock).toBeTypeOf('function');
    await exports.startMock!();
    expect(start).toHaveBeenCalledWith({ onUnhandledFrame: 'bypass', quiet: true });
  });

  it('serves the worker supplied by the installed MSW version', async () => {
    const served = await readFile(join(webRoot, 'mock/public/mockServiceWorker.js'), 'utf8');
    const installed = await readFile(require.resolve('msw/mockServiceWorker.js'), 'utf8');
    expect(served).toBe(installed);
  });

  it('blocks an unmocked request before it reaches a real server', async () => {
    let requests = 0;
    const upstream = createServer((_request, response) => {
      requests++;
      response.end('fixture');
    });
    const server = setupServer();
    let listening = false;
    vi.spyOn(console, 'error').mockImplementation(() => {});
    await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
    const address = upstream.address();
    if (!address || typeof address === 'string') throw new Error('missing fixture address');
    try {
      const url = `http://127.0.0.1:${address.port}/unmocked`;
      server.listen({ onUnhandledFrame: 'error' });
      listening = true;
      await expect(fetch(url)).rejects.toMatchObject({
        cause: expect.objectContaining({
          message: '[MSW] Cannot bypass a request when using the "error" strategy for the "onUnhandledFrame" option.',
        }),
      });
      expect(requests).toBe(0);
      server.close();
      listening = false;
      expect(await (await fetch(url)).text()).toBe('fixture');
      expect(requests).toBe(1);
    } finally {
      if (listening) server.close();
      upstream.closeAllConnections();
      await new Promise<void>((resolve, reject) => upstream.close((error) => error ? reject(error) : resolve()));
    }
  });

  it('excludes the worker and mock runtime from production output', async () => {
    const outDir = await mkdtemp(join(tmpdir(), 'deckard-msw-production-'));
    const env: NodeJS.ProcessEnv = { ...process.env, NODE_ENV: 'production' };
    delete env.VITE_MOCK;
    try {
      const vite = join(dirname(require.resolve('vite/package.json')), 'bin/vite.js');
      execFileSync(process.execPath, [vite, 'build', '--outDir', outDir, '--emptyOutDir'], {
        cwd: webRoot, env, stdio: 'pipe', timeout: 20_000,
      });
      expect(await readdir(outDir)).not.toContain('mockServiceWorker.js');
      const assets = await readdir(join(outDir, 'assets'));
      const scripts = assets.filter((name) => name.endsWith('.js'));
      expect(scripts.length).toBeGreaterThan(0);
      const bodies = await Promise.all(scripts.map((name) => readFile(join(outDir, 'assets', name), 'utf8')));
      for (const marker of ['mockServiceWorker', 'msw/worker', 'Mock Service Worker', 'Mocking enabled', 'promo.example.com']) {
        expect(bodies.some((body) => body.includes(marker))).toBe(false);
      }
    } finally {
      await rm(outDir, { recursive: true });
    }
  }, 25_000);
});
