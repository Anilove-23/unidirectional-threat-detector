import { NavLink } from 'react-router-dom';

const TABS = [
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/alerts', label: 'Alerts' },
];

export default function NavTabs() {
  return (
    <nav className="border-b border-border bg-surface-1 px-4 sm:px-6">
      <div className="flex gap-1">
        {TABS.map((tab) => (
          <NavLink
            key={tab.to}
            to={tab.to}
            className={({ isActive }) =>
              `border-b-2 px-3 py-2.5 text-sm font-medium transition-colors ${
                isActive
                  ? 'border-signal text-ink-primary'
                  : 'border-transparent text-ink-muted hover:text-ink-secondary'
              }`
            }
          >
            {tab.label}
          </NavLink>
        ))}
      </div>
    </nav>
  );
}
