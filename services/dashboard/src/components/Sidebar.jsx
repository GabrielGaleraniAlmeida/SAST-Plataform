import { NavLink, useLocation } from 'react-router-dom'
import {
  LayoutDashboard,
  ScanLine,
  ShieldAlert,
  Settings,
  ChevronRight,
  Shield,
} from 'lucide-react'

/**
 * Application sidebar with navigation links and active state highlighting.
 * Uses React Router's NavLink for automatic active state detection.
 */

const NAV_ITEMS = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard', exact: true },
  { to: '/scans', icon: ScanLine, label: 'Scans' },
  { to: '/vulnerabilities', icon: ShieldAlert, label: 'Vulnerabilities' },
]

function NavItem({ to, icon: Icon, label, exact }) {
  return (
    <NavLink
      to={to}
      end={exact}
      className={({ isActive }) =>
        `group flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 ${
          isActive
            ? 'bg-brand-600 text-white shadow-sm shadow-brand-900/30'
            : 'text-slate-400 hover:bg-slate-800 hover:text-slate-100'
        }`
      }
    >
      {({ isActive }) => (
        <>
          <Icon className="h-4 w-4 flex-shrink-0" />
          <span className="flex-1">{label}</span>
          {isActive && <ChevronRight className="h-3 w-3 opacity-70" />}
        </>
      )}
    </NavLink>
  )
}

export default function Sidebar() {
  return (
    <aside className="flex flex-col w-60 min-w-[240px] bg-slate-900 border-r border-slate-800 h-screen">
      {/* Logo / Brand */}
      <div className="flex items-center gap-3 px-5 py-5 border-b border-slate-800">
        <div className="flex items-center justify-center w-9 h-9 bg-brand-600 rounded-lg shadow-lg shadow-brand-900/40">
          <Shield className="h-5 w-5 text-white" />
        </div>
        <div>
          <p className="text-white font-bold text-sm leading-tight">SAST Platform</p>
          <p className="text-slate-500 text-xs">Security Analysis</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        <p className="px-3 mb-2 text-xs font-semibold text-slate-600 uppercase tracking-wider">
          Main
        </p>
        {NAV_ITEMS.map((item) => (
          <NavItem key={item.to} {...item} />
        ))}
      </nav>

      {/* Footer */}
      <div className="px-3 py-4 border-t border-slate-800">
        <NavLink
          to="/settings"
          className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm text-slate-400 hover:bg-slate-800 hover:text-slate-100 transition-colors"
        >
          <Settings className="h-4 w-4" />
          Settings
        </NavLink>
        <div className="mt-3 px-3 py-2">
          <p className="text-xs text-slate-600">v1.0.0 • SAST Platform</p>
        </div>
      </div>
    </aside>
  )
}
