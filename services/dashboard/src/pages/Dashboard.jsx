import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  PieChart, Pie, Cell, Tooltip as ReTooltip, Legend, ResponsiveContainer,
  LineChart, Line, XAxis, YAxis, CartesianGrid,
  BarChart, Bar,
} from 'recharts'
import {
  ShieldAlert, ScanLine, FileCode2, AlertTriangle,
  TrendingUp, ArrowRight, RefreshCw,
} from 'lucide-react'
import {
  getOverviewStats,
  getSeverityDistribution,
  getVulnerabilityTrend,
  getTopVulnerableFiles,
  getVulnerabilitiesByRule,
} from '../api/stats'
import { getScans } from '../api/scans'
import SeverityBadge from '../components/SeverityBadge'

// ── Colour mappings ────────────────────────────────────────────────────────
const SEVERITY_COLORS = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#60a5fa',
  info:     '#94a3b8',
}

const STATUS_CONFIG = {
  completed: 'bg-green-100 text-green-800',
  running:   'bg-blue-100 text-blue-800',
  pending:   'bg-gray-100 text-gray-700',
  failed:    'bg-red-100 text-red-800',
}

// ── Sub-components ─────────────────────────────────────────────────────────

function StatCard({ icon: Icon, label, value, sub, iconBg, loading }) {
  return (
    <div className="stat-card">
      <div className={`flex items-center justify-center w-11 h-11 rounded-xl ${iconBg}`}>
        <Icon className="h-5 w-5 text-white" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-xs text-gray-500 font-medium truncate">{label}</p>
        {loading ? (
          <div className="h-7 w-20 bg-gray-100 animate-pulse rounded mt-1" />
        ) : (
          <p className="text-2xl font-bold text-gray-900 tabular-nums">{value ?? '—'}</p>
        )}
        {sub && <p className="text-xs text-gray-400 mt-0.5">{sub}</p>}
      </div>
    </div>
  )
}

function SectionHeader({ title, children }) {
  return (
    <div className="flex items-center justify-between mb-4">
      <h2 className="text-sm font-semibold text-gray-900">{title}</h2>
      {children}
    </div>
  )
}

function ChartSkeleton() {
  return <div className="w-full h-56 bg-gray-50 animate-pulse rounded-lg" />
}

function CustomPieTooltip({ active, payload }) {
  if (active && payload?.length) {
    const { name, value } = payload[0]
    return (
      <div className="bg-white border border-gray-200 rounded-lg px-3 py-2 shadow-lg text-sm">
        <SeverityBadge severity={name} size="sm" />
        <p className="mt-1 text-gray-800 font-semibold">{value} vulnerabilities</p>
      </div>
    )
  }
  return null
}

// ── Main Dashboard ─────────────────────────────────────────────────────────

export default function Dashboard() {
  const overview = useQuery({ queryKey: ['stats', 'overview'], queryFn: getOverviewStats })
  const severity = useQuery({ queryKey: ['stats', 'severity'], queryFn: getSeverityDistribution })
  const trend    = useQuery({ queryKey: ['stats', 'trend'], queryFn: () => getVulnerabilityTrend(30) })
  const topFiles = useQuery({ queryKey: ['stats', 'top-files'], queryFn: () => getTopVulnerableFiles(5) })
  const byRule   = useQuery({ queryKey: ['stats', 'by-rule'], queryFn: () => getVulnerabilitiesByRule(8) })
  const recentScans = useQuery({
    queryKey: ['scans', { page: 1, page_size: 5 }],
    queryFn: () => getScans({ page: 1, page_size: 5 }),
  })

  const o = overview.data || {}
  const pieData = (severity.data || []).map((d) => ({
    name: d.severity,
    value: d.count,
    fill: SEVERITY_COLORS[d.severity] || '#94a3b8',
  }))

  return (
    <div className="p-6 space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-900">Security Dashboard</h1>
          <p className="text-sm text-gray-500 mt-0.5">Platform-wide vulnerability overview</p>
        </div>
        <button
          onClick={() => {
            overview.refetch()
            severity.refetch()
            trend.refetch()
            topFiles.refetch()
            byRule.refetch()
            recentScans.refetch()
          }}
          className="btn-secondary text-xs"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh
        </button>
      </div>

      {/* ── Stat cards ── */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        <StatCard
          icon={ScanLine}
          label="Total Scans"
          value={o.total_scans?.toLocaleString()}
          sub={`${o.scans_this_week ?? 0} this week`}
          iconBg="bg-brand-600"
          loading={overview.isLoading}
        />
        <StatCard
          icon={ShieldAlert}
          label="Total Vulnerabilities"
          value={o.total_vulnerabilities?.toLocaleString()}
          iconBg="bg-orange-500"
          loading={overview.isLoading}
        />
        <StatCard
          icon={AlertTriangle}
          label="Critical Issues"
          value={o.critical_count?.toLocaleString()}
          iconBg="bg-red-600"
          loading={overview.isLoading}
        />
        <StatCard
          icon={FileCode2}
          label="Files Analyzed"
          value={o.files_analyzed?.toLocaleString()}
          iconBg="bg-emerald-600"
          loading={overview.isLoading}
        />
      </div>

      {/* ── Charts row 1 ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity donut */}
        <div className="card">
          <SectionHeader title="Severity Distribution" />
          {severity.isLoading ? (
            <ChartSkeleton />
          ) : pieData.length === 0 ? (
            <div className="h-56 flex items-center justify-center text-gray-400 text-sm">
              No data available
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={90}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {pieData.map((entry) => (
                    <Cell key={entry.name} fill={entry.fill} stroke="transparent" />
                  ))}
                </Pie>
                <ReTooltip content={<CustomPieTooltip />} />
                <Legend
                  iconType="circle"
                  iconSize={8}
                  formatter={(value) => (
                    <span className="text-xs text-gray-600 capitalize">{value}</span>
                  )}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Vulnerability trend */}
        <div className="card">
          <SectionHeader title="Vulnerability Trend (30 days)">
            <TrendingUp className="h-4 w-4 text-gray-400" />
          </SectionHeader>
          {trend.isLoading ? (
            <ChartSkeleton />
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={trend.data || []} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                <XAxis
                  dataKey="date"
                  tick={{ fontSize: 10, fill: '#9ca3af' }}
                  tickLine={false}
                  axisLine={false}
                  tickFormatter={(v) => {
                    const d = new Date(v)
                    return `${d.getMonth() + 1}/${d.getDate()}`
                  }}
                  interval="preserveStartEnd"
                />
                <YAxis tick={{ fontSize: 10, fill: '#9ca3af' }} tickLine={false} axisLine={false} />
                <ReTooltip
                  contentStyle={{ fontSize: 12, borderRadius: 8, border: '1px solid #e5e7eb' }}
                  labelFormatter={(v) => new Date(v).toLocaleDateString()}
                />
                <Line
                  type="monotone"
                  dataKey="count"
                  stroke="#4f46e5"
                  strokeWidth={2}
                  dot={false}
                  activeDot={{ r: 5, fill: '#4f46e5' }}
                />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* ── Charts row 2 ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top vulnerable files */}
        <div className="card">
          <SectionHeader title="Top 5 Vulnerable Files" />
          {topFiles.isLoading ? (
            <ChartSkeleton />
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart
                data={topFiles.data || []}
                layout="vertical"
                margin={{ top: 0, right: 10, left: 0, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#f0f0f0" />
                <XAxis type="number" tick={{ fontSize: 10, fill: '#9ca3af' }} tickLine={false} axisLine={false} />
                <YAxis
                  type="category"
                  dataKey="file_path"
                  tick={{ fontSize: 10, fill: '#6b7280' }}
                  tickLine={false}
                  axisLine={false}
                  width={130}
                  tickFormatter={(v) => {
                    const parts = v.split('/')
                    return parts.length > 2 ? `…/${parts.slice(-2).join('/')}` : v
                  }}
                />
                <ReTooltip
                  contentStyle={{ fontSize: 12, borderRadius: 8, border: '1px solid #e5e7eb' }}
                />
                <Bar dataKey="count" name="Vulnerabilities" fill="#ef4444" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Vulnerabilities by rule */}
        <div className="card">
          <SectionHeader title="Vulnerabilities by Rule" />
          {byRule.isLoading ? (
            <ChartSkeleton />
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={byRule.data || []} margin={{ top: 0, right: 10, left: -20, bottom: 30 }}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f0f0f0" />
                <XAxis
                  dataKey="rule_id"
                  tick={{ fontSize: 9, fill: '#6b7280' }}
                  tickLine={false}
                  axisLine={false}
                  angle={-35}
                  textAnchor="end"
                  interval={0}
                />
                <YAxis tick={{ fontSize: 10, fill: '#9ca3af' }} tickLine={false} axisLine={false} />
                <ReTooltip
                  contentStyle={{ fontSize: 12, borderRadius: 8, border: '1px solid #e5e7eb' }}
                />
                <Bar dataKey="count" name="Count" fill="#f97316" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* ── Recent scans table ── */}
      <div className="card p-0 overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-gray-900">Recent Scans</h2>
          <Link to="/scans" className="text-xs text-brand-600 hover:text-brand-700 font-medium flex items-center gap-1">
            View all <ArrowRight className="h-3 w-3" />
          </Link>
        </div>
        {recentScans.isLoading ? (
          <div className="p-6 space-y-3">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="h-10 bg-gray-50 animate-pulse rounded" />
            ))}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Repository</th>
                  <th>Branch</th>
                  <th>Language</th>
                  <th>Status</th>
                  <th>Vulns</th>
                  <th>Date</th>
                  <th />
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {(recentScans.data?.items || []).length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-8 text-center text-gray-400 text-sm">
                      No scans yet
                    </td>
                  </tr>
                ) : (
                  (recentScans.data?.items || []).map((scan) => (
                    <tr key={scan.id}>
                      <td className="max-w-[200px]">
                        <p className="truncate font-medium text-gray-900" title={scan.repository_url}>
                          {scan.repository_url?.replace(/^https?:\/\//, '')}
                        </p>
                      </td>
                      <td>
                        <span className="font-mono text-xs bg-gray-100 px-2 py-0.5 rounded">
                          {scan.branch}
                        </span>
                      </td>
                      <td className="capitalize">{scan.language || '—'}</td>
                      <td>
                        <span className={`inline-flex text-xs font-medium px-2 py-0.5 rounded-full ${STATUS_CONFIG[scan.status] || STATUS_CONFIG.pending}`}>
                          {scan.status}
                        </span>
                      </td>
                      <td>
                        <span className="font-semibold tabular-nums">
                          {scan.vulnerability_count ?? '—'}
                        </span>
                      </td>
                      <td className="text-gray-400 text-xs">
                        {scan.created_at
                          ? new Date(scan.created_at).toLocaleDateString()
                          : '—'}
                      </td>
                      <td>
                        <Link
                          to={`/scans/${scan.id}`}
                          className="text-brand-600 hover:text-brand-700 text-xs font-medium"
                        >
                          Details
                        </Link>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
