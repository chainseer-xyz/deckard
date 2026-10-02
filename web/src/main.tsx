import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import './index.css';
import App from './App';
import { applyTheme, loadTheme } from './lib/theme';

applyTheme(loadTheme());

async function boot() {
  if (import.meta.env.VITE_MOCK === '1') {
    const { startMock } = await import('../mock/browser');
    await startMock();
  }
  const root = document.getElementById('root');
  if (!root) throw new Error('missing #root');
  createRoot(root).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}
void boot();
