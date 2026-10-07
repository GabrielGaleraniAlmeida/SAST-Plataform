import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import ScansList from './pages/ScansList'
import ScanDetail from './pages/ScanDetail'
import VulnerabilitiesList from './pages/VulnerabilitiesList'

/**
 * Root application component.
 * Provides the shell layout (sidebar + main content area) and React Router routes.
 */
export default function App() {
  return (
    <BrowserRouter>
      <div className="flex h-screen bg-gray-50 overflow-hidden">
        {/* Persistent sidebar navigation */}
        <Sidebar />

        {/* Main scrollable content area */}
        <main className="flex-1 overflow-y-auto">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scans" element={<ScansList />} />
            <Route path="/scans/:id" element={<ScanDetail />} />
            <Route path="/vulnerabilities" element={<VulnerabilitiesList />} />
            {/* Catch-all redirect */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
