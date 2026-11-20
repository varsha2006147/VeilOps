import type { ReactNode } from 'react';
import { NavLink } from 'react-router-dom';
import TokenBar from './TokenBar';
import { USE_MOCK } from '../api';

interface TopBarProps {
  tenant?: string;
  controls?: ReactNode;
}

const links = [
  { to: '/', label: 'Live' },
  { to: '/incidents', label: 'Incidents' },
  { to: '/summary', label: 'Summary' },
  { to: '/about', label: 'How it works' },
];

export default function TopBar({ tenant = USE_MOCK ? 'acme' : '—', controls }: TopBarProps) {
  return (
    <><header className="top-bar">
      <div className="brand">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M12 3l8 3v6c0 4.5-3.2 8-8 9.5C7.2 20 4 16.5 4 12V6z"
            stroke="var(--text)" strokeWidth="1.7" strokeLinejoin="round" />
        </svg>
        <span className="brand-name">VeilOps</span>
        <span className="tenant">{tenant}</span>
      </div>
      <nav className="top-nav" aria-label="Main navigation">
        {links.map(({ to, label }) => (
          <NavLink key={to} to={to} end={to === '/'}
            className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>
            {label}
          </NavLink>
        ))}
      </nav>
      <div className="top-controls">{controls}</div>
    </header><TokenBar /></>
  );
}
