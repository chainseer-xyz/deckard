import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import logo from '../assets/deckard-logo.svg?raw';
import mark from '../assets/deckard-mark.svg?raw';
import { Brand } from './Brand';
import { Layout } from './Layout';
import { Login } from '../pages/Login';
import { renderRoute } from '../test/utils';

vi.mock('../api/hooks', () => ({ useMe: () => ({ data: { identity: 'operator', can_write: true } }) }));

const parse = (source: string) => new DOMParser().parseFromString(source, 'image/svg+xml');

describe('Deckard identity', () => {
  it('renders the canonical logo with one accessible product name', () => {
    render(<Brand className="h-8" />);
    const graphic = screen.getByRole('img', { name: 'Deckard' });
    expect(graphic.tagName.toLowerCase()).toBe('svg');
    expect(graphic.querySelector('.deckard-wordmark')?.getAttribute('d')).toBeTruthy();
    expect(graphic.querySelector('.deckard-wordmark')?.getAttribute('d')).toBe(
      parse(logo).querySelector('.deckard-wordmark')?.getAttribute('d'),
    );
    expect(graphic.parentElement).toHaveClass('brand-logo', 'h-8');
  });

  it.each([['logo', logo], ['mark', mark]])('%s is self-contained vector artwork', (_name, source) => {
    const graphic = parse(source);
    expect(graphic.querySelector('parsererror')).toBeNull();
    expect(graphic.documentElement.getAttribute('role')).toBe('img');
    expect(graphic.documentElement.getAttribute('aria-label')).toBe('Deckard');
    expect(graphic.querySelector('title')?.textContent).toBe('Deckard');
    expect(graphic.querySelector('script, foreignObject, image, text, animate')).toBeNull();
    for (const element of graphic.querySelectorAll('*')) {
      for (const attribute of element.attributes) {
        expect(attribute.localName).not.toMatch(/^on|href/i);
      }
    }
    expect(source).not.toMatch(/url\(|@font-face|font-family/);
    expect(source.length).toBeLessThan(12000);
  });

  it('uses the same monogram in the logo and favicon', () => {
    expect(parse(mark).querySelector('path')?.getAttribute('d')).toBeTruthy();
    expect(parse(logo).querySelector('.deckard-mark')?.getAttribute('d')).toBeTruthy();
    expect(parse(mark).querySelector('path')?.getAttribute('d')).toBe(
      parse(logo).querySelector('.deckard-mark')?.getAttribute('d'),
    );
    const html = readFileSync(resolve(process.cwd(), 'index.html'), 'utf8');
    expect(html).toContain('/src/assets/deckard-mark.svg');
    expect(html).toContain('<title>Deckard</title>');
  });

  it('uses the canonical logo as the README heading, not a separate banner or lowercase name', () => {
    const readme = readFileSync(resolve(process.cwd(), '../README.md'), 'utf8');
    expect(readme.split('\n').slice(0, 4).join('\n')).toMatch(
      /<h1 align="center">\s*<img src="web\/src\/assets\/deckard-logo.svg" alt="Deckard"/,
    );
    expect(readme).not.toContain('readme-hero.svg');
  });

  it('shows the logo in the application header without replacing navigation', () => {
    renderRoute(<Layout />);
    expect(screen.getByRole('banner')).toContainElement(screen.getByRole('img', { name: 'Deckard' }));
    expect(screen.getByRole('navigation', { name: 'Main' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Inventory' })).toHaveAttribute('href', '/inventory');
  });

  it('shows the same logo on sign-in and uses product casing in prose', () => {
    renderRoute(<Login />);
    expect(screen.getByRole('img', { name: 'Deckard' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Sign in to Deckard' })).toBeInTheDocument();
    expect(screen.getByLabelText('API token')).toHaveAttribute('type', 'password');
  });
});
