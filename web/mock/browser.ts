import { setupWorker } from 'msw/browser';
import { makeHandlers } from './handlers';

export async function startMock(): Promise<void> {
  await setupWorker(...makeHandlers()).start({ onUnhandledFrame: 'bypass', quiet: true });
}
