/**
 * SeverityBadge — reusable pill badge for SAST severity levels.
 *
 * Props:
 *   severity {string} — "critical" | "high" | "medium" | "low" | "info"
 *   size     {string} — "sm" | "md" (default "md")
 */

const SEVERITY_CONFIG = {
  critical: {
    label: 'Critical',
    classes: 'bg-red-100 text-red-800 ring-red-200',
    dot: 'bg-red-500',
  },
  high: {
    label: 'High',
    classes: 'bg-orange-100 text-orange-800 ring-orange-200',
    dot: 'bg-orange-500',
  },
  medium: {
    label: 'Medium',
    classes: 'bg-yellow-100 text-yellow-800 ring-yellow-200',
    dot: 'bg-yellow-500',
  },
  low: {
    label: 'Low',
    classes: 'bg-blue-100 text-blue-800 ring-blue-200',
    dot: 'bg-blue-400',
  },
  info: {
    label: 'Info',
    classes: 'bg-gray-100 text-gray-700 ring-gray-200',
    dot: 'bg-gray-400',
  },
}

export default function SeverityBadge({ severity, size = 'md' }) {
  const key = (severity || 'info').toLowerCase()
  const config = SEVERITY_CONFIG[key] || SEVERITY_CONFIG.info

  const sizeClasses =
    size === 'sm'
      ? 'px-1.5 py-0.5 text-xs gap-1'
      : 'px-2.5 py-1 text-xs font-semibold gap-1.5'

  return (
    <span
      className={`inline-flex items-center rounded-full ring-1 ring-inset ${config.classes} ${sizeClasses}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${config.dot}`} />
      {config.label}
    </span>
  )
}
