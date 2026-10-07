import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Plus, ChevronLeft, ChevronRight, ExternalLink, ScanLine } from 'lucide-react'
import { getScans } from '../api/scans'
import ScanModal from '../components/ScanModal'

/** Status badge configuration */
const STATUS_CONFIG = {
  completed: { label: 'Completed', classes: 'bg-green-100 text-green-800 ring-green-200' },
  running:   { label: 'Running',   classes: 'bg-blue-100  text-blue-800  ring-blue-200' },
  pending:   { label: 'Pending',   classes: 'bg-gray-100  text-gray-700  ring-gray-200' },
  failed:    { label: 'Failed',    classes: 'bg-red-100   text-red-800   ring-red-200'  },
}

function StatusBadge({ status }) {
  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.pending
  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ring-1 ring-inset ${cfg.classes}`}
    >
      {/* Animated dot for running state */}
      {status === 'running' && (
        <span className="mr-1.5 h-1.5 w-1.5 rounded-full bg-blue-500 animate-pulse" />
      )}
      {cfg.label}
    </span>
  )
}

function Pagination({ page, totalPages, onPageChange }) {
  if (totalPages <= 1) return null
  return (
    <div className="flex items-center justify-between px-5 py-3 border-t border-gray-100">
      <p className="text-xs text-gray-500">
        Page {page} of {totalPages}
      </p>
      <div className="flex items-center gap-1">
        <button
          onClick={() => onPageChange(page - 1)}
          disabled={page === 1}
          className="p-1.5 rounded-md text-gray-500 hover:bg-gray-100 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          <ChevronLeft className="h-4 w-4" />
        </button>
        {[...Array(Math.min(totalPages, 7))].map((_, i) => {
          const p = i + 1
          return (
            <button
              key={p}
              onClick={() => onPageChange(p)}
              className={`w-7 h-7 text-xs rounded-md transition-colors ${
                p === page
                  ? 'bg-brand-600 text-white font-semibold'
                  : 'text-gray-600 hover:bg-gray-100'
              }`}
            >
              {p}
            </button>
          )
        })}
        <button
          onClick={() => onPageChange(page + 1)}
          disabled={page === totalPages}
          className="p-1.5 rounded-md text-gray-500 hover:bg-gray-100 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          <ChevronRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  )
}

export default function ScansList() {
  const [page, setPage] = useState(1)
  const [modalOpen, setModalOpen] = useState(false)
  const PAGE_SIZE = 15

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['scans', { page, page_size: PAGE_SIZE }],
    queryFn: () => getScans({ page, page_size: PAGE_SIZE }),
    keepPreviousData: true,
  })

  const scans = data?.items || []
  const total = data?.total || 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-900">Scans</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            {isLoading ? 'Loading…' : `${total.toLocaleString()} total scan${total !== 1 ? 's' : ''}`}
          </p>
        </div>
        <button onClick={() => setModalOpen(true)} className="btn-primary">
          <Plus className="h-4 w-4" />
          New Scan
        </button>
      </div>

      {/* Table card */}
      <div className="card p-0 overflow-hidden">
        {isError && (
          <div className="px-5 py-4 bg-red-50 border-b border-red-200 text-sm text-red-700">
            {error?.displayMessage || 'Failed to load scans.'}
          </div>
        )}
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Repository</th>
                <th>Branch</th>
                <th>Language</th>
                <th>Status</th>
                <th>Vulnerabilities</th>
                <th>Date</th>
                <th />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {isLoading ? (
                [...Array(8)].map((_, i) => (
                  <tr key={i}>
                    {[...Array(8)].map((__, j) => (
                      <td key={j}>
                        <div className="h-4 bg-gray-100 animate-pulse rounded w-full" />
                      </td>
                    ))}
                  </tr>
                ))
              ) : scans.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-16 text-center">
                    <ScanLine className="h-10 w-10 text-gray-200 mx-auto mb-3" />
                    <p className="text-gray-500 text-sm font-medium">No scans found</p>
                    <p className="text-gray-400 text-xs mt-1">Click "New Scan" to get started</p>
                  </td>
                </tr>
              ) : (
                scans.map((scan) => (
                  <tr key={scan.id}>
                    <td className="text-gray-400 font-mono text-xs">#{scan.id}</td>
                    <td className="max-w-[220px]">
                      <div className="flex items-center gap-1.5 min-w-0">
                        <p className="truncate text-sm font-medium text-gray-900" title={scan.repository_url}>
                          {scan.repository_url?.replace(/^https?:\/\//, '')}
                        </p>
                        <a
                          href={scan.repository_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex-shrink-0 text-gray-400 hover:text-gray-600"
                        >
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      </div>
                    </td>
                    <td>
                      <span className="font-mono text-xs bg-gray-100 px-2 py-0.5 rounded">
                        {scan.branch}
                      </span>
                    </td>
                    <td className="capitalize text-sm">{scan.language || '—'}</td>
                    <td>
                      <StatusBadge status={scan.status} />
                    </td>
                    <td>
                      <span
                        className={`font-semibold tabular-nums text-sm ${
                          (scan.vulnerability_count || 0) > 0 ? 'text-red-600' : 'text-gray-700'
                        }`}
                      >
                        {scan.vulnerability_count ?? '—'}
                      </span>
                    </td>
                    <td className="text-gray-400 text-xs whitespace-nowrap">
                      {scan.created_at
                        ? new Date(scan.created_at).toLocaleString()
                        : '—'}
                    </td>
                    <td>
                      <Link
                        to={`/scans/${scan.id}`}
                        className="text-brand-600 hover:text-brand-700 text-xs font-medium"
                      >
                        View →
                      </Link>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        <Pagination page={page} totalPages={totalPages} onPageChange={setPage} />
      </div>

      {/* New scan modal */}
      <ScanModal isOpen={modalOpen} onClose={() => setModalOpen(false)} />
    </div>
  )
}
