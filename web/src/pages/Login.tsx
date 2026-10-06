import { useState } from 'react';
import type { FormEvent } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { setToken } from '../api/auth';
import { ThemeToggle } from '../components/Layout';
import { Brand } from '../components/Brand';

export function Login({ message }: { message?: string }) {
  const qc = useQueryClient();
  const [token, setTok] = useState('');
  const [err, setErr] = useState('');

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!token.trim()) {
      setErr('Enter an API token.');
      return;
    }
    setErr('');
    setToken(token.trim());
    void qc.resetQueries({ queryKey: ['me'] });
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <div className="absolute right-4 top-4">
        <ThemeToggle />
      </div>
      <form onSubmit={submit} className="card w-full max-w-sm space-y-4 p-6" aria-labelledby="login-h" noValidate>
        <div>
          <Brand className="mb-4 h-14" />
          <h1 id="login-h" className="text-lg font-semibold">Sign in to Deckard</h1>
          <p className="mt-1 text-xs text-muted">
            Paste an API bearer token. It is kept in this tab only (sessionStorage) and cleared when the tab closes.
          </p>
        </div>
        <div>
          <label htmlFor="token" className="mb-1 block text-sm font-medium">
            API token
          </label>
          <input
            id="token"
            type="password"
            autoComplete="off"
            spellCheck={false}
            className="input w-full font-mono"
            value={token}
            onChange={(e) => setTok(e.target.value)}
            aria-invalid={!!(err || message)}
          />
        </div>
        {(err || message) && (
          <p role="alert" className="text-sm text-bad">
            {err || message}
          </p>
        )}
        <button type="submit" className="btn btn-primary w-full justify-center">
          Sign in
        </button>
      </form>
    </div>
  );
}
