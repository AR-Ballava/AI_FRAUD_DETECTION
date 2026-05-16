import { BarChart3, Network, SearchCheck, ShieldCheck, Zap } from 'lucide-react';

const navItems = [
  { id: 'detect', label: 'Detect Fraud', icon: <Zap size={16} /> },
  { id: 'osint', label: 'OSINT', icon: <SearchCheck size={16} /> },
  { id: 'graph', label: 'Graph Map', icon: <Network size={16} /> },
  { id: 'analytics', label: 'Analytics', icon: <BarChart3 size={16} /> },
];

function Header({ currentPage, onNavigate }) {
  return (
    <header className="app-header">
      <button className="brand" type="button" onClick={() => onNavigate('detect')} aria-label="Fraud Shield home">
        <span className="brand-mark">
          <ShieldCheck size={22} />
        </span>
        <span>
          Fraud <strong>Shield</strong>
        </span>
      </button>
      <nav>
        {navItems.map((item) => (
          <button
            className={currentPage === item.id ? 'active' : ''}
            key={item.id}
            type="button"
            onClick={() => onNavigate(item.id)}
          >
            {item.icon}
            {item.label}
          </button>
        ))}
      </nav>
    </header>
  );
}

export default Header;
