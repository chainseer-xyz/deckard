import logo from '../assets/deckard-logo.svg?raw';

/** Only this version-controlled vector is inlined; never pass API data here. */
export function Brand({ className = '' }: { className?: string }) {
  return <span className={`brand-logo ${className}`} dangerouslySetInnerHTML={{ __html: logo }} />;
}
