import { useEffect, type ReactNode } from 'react';
import TopBar from './TopBar';

interface PageProps {
  title: string;
  controls?: ReactNode;
  children?: ReactNode;
}

export default function Page({ title, controls, children }: PageProps) {
  useEffect(() => { document.title = `${title} · VeilOps`; }, [title]);
  return (
    <div className="app-shell">
      <a className="skip-link" href="#main">Skip to content</a>
      <TopBar controls={controls} />
      <main id="main" className="page" tabIndex={-1}>
        <h1>{title}</h1>
        {children}
      </main>
    </div>
  );
}
