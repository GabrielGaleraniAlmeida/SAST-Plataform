import { Fragment, useState } from 'react'
import { Dialog, Transition } from '@headlessui/react'
import { X, GitBranch, Globe, Code2 } from 'lucide-react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { createScan } from '../api/scans'

/**
 * ScanModal — headless-UI dialog for creating a new SAST scan.
 *
 * Props:
 *   isOpen   {boolean}  — controls dialog visibility
 *   onClose  {Function} — called when dialog should close
 */

const LANGUAGES = [
  { value: '', label: 'Auto-detect' },
  { value: 'python', label: 'Python' },
  { value: 'javascript', label: 'JavaScript' },
  { value: 'typescript', label: 'TypeScript' },
  { value: 'java', label: 'Java' },
]

const INITIAL_FORM = { repository_url: '', branch: 'main', language: '' }

export default function ScanModal({ isOpen, onClose }) {
  const [form, setForm] = useState(INITIAL_FORM)
  const [errors, setErrors] = useState({})
  const queryClient = useQueryClient()

  const mutation = useMutation({
    mutationFn: createScan,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      queryClient.invalidateQueries({ queryKey: ['stats'] })
      handleClose()
    },
  })

  const validate = () => {
    const errs = {}
    if (!form.repository_url.trim()) {
      errs.repository_url = 'Repository URL is required'
    } else if (!/^https?:\/\/.+/.test(form.repository_url.trim())) {
      errs.repository_url = 'Enter a valid HTTP(S) URL'
    }
    if (!form.branch.trim()) {
      errs.branch = 'Branch is required'
    }
    return errs
  }

  const handleSubmit = (e) => {
    e.preventDefault()
    const errs = validate()
    if (Object.keys(errs).length) {
      setErrors(errs)
      return
    }
    setErrors({})
    mutation.mutate({
      repository_url: form.repository_url.trim(),
      branch: form.branch.trim(),
      language: form.language || null,
    })
  }

  const handleClose = () => {
    setForm(INITIAL_FORM)
    setErrors({})
    mutation.reset()
    onClose()
  }

  return (
    <Transition appear show={isOpen} as={Fragment}>
      <Dialog as="div" className="relative z-50" onClose={handleClose}>
        {/* Backdrop */}
        <Transition.Child
          as={Fragment}
          enter="ease-out duration-200"
          enterFrom="opacity-0"
          enterTo="opacity-100"
          leave="ease-in duration-150"
          leaveFrom="opacity-100"
          leaveTo="opacity-0"
        >
          <div className="fixed inset-0 bg-black/40 backdrop-blur-sm" />
        </Transition.Child>

        <div className="fixed inset-0 overflow-y-auto">
          <div className="flex min-h-full items-center justify-center p-4">
            <Transition.Child
              as={Fragment}
              enter="ease-out duration-200"
              enterFrom="opacity-0 scale-95"
              enterTo="opacity-100 scale-100"
              leave="ease-in duration-150"
              leaveFrom="opacity-100 scale-100"
              leaveTo="opacity-0 scale-95"
            >
              <Dialog.Panel className="w-full max-w-md transform overflow-hidden rounded-2xl bg-white shadow-2xl ring-1 ring-black/5 transition-all">
                {/* Header */}
                <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
                  <Dialog.Title className="text-base font-semibold text-gray-900">
                    New Security Scan
                  </Dialog.Title>
                  <button
                    onClick={handleClose}
                    className="p-1 rounded-md text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition-colors"
                  >
                    <X className="h-4 w-4" />
                  </button>
                </div>

                {/* Form */}
                <form onSubmit={handleSubmit} className="px-6 py-5 space-y-4">
                  {/* Repository URL */}
                  <div>
                    <label className="form-label" htmlFor="repo-url">
                      Repository URL
                    </label>
                    <div className="relative">
                      <Globe className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
                      <input
                        id="repo-url"
                        type="url"
                        className={`form-input pl-9 ${errors.repository_url ? 'border-red-400 focus:ring-red-500' : ''}`}
                        placeholder="https://github.com/org/repo"
                        value={form.repository_url}
                        onChange={(e) => setForm({ ...form, repository_url: e.target.value })}
                      />
                    </div>
                    {errors.repository_url && (
                      <p className="mt-1 text-xs text-red-600">{errors.repository_url}</p>
                    )}
                  </div>

                  {/* Branch */}
                  <div>
                    <label className="form-label" htmlFor="branch">
                      Branch
                    </label>
                    <div className="relative">
                      <GitBranch className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
                      <input
                        id="branch"
                        type="text"
                        className={`form-input pl-9 ${errors.branch ? 'border-red-400 focus:ring-red-500' : ''}`}
                        placeholder="main"
                        value={form.branch}
                        onChange={(e) => setForm({ ...form, branch: e.target.value })}
                      />
                    </div>
                    {errors.branch && (
                      <p className="mt-1 text-xs text-red-600">{errors.branch}</p>
                    )}
                  </div>

                  {/* Language */}
                  <div>
                    <label className="form-label" htmlFor="language">
                      Language
                    </label>
                    <div className="relative">
                      <Code2 className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
                      <select
                        id="language"
                        className="form-select pl-9"
                        value={form.language}
                        onChange={(e) => setForm({ ...form, language: e.target.value })}
                      >
                        {LANGUAGES.map((l) => (
                          <option key={l.value} value={l.value}>
                            {l.label}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>

                  {/* API error */}
                  {mutation.isError && (
                    <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-3">
                      <p className="text-sm text-red-700">
                        {mutation.error?.displayMessage || 'Failed to create scan.'}
                      </p>
                    </div>
                  )}

                  {/* Actions */}
                  <div className="flex items-center justify-end gap-3 pt-2">
                    <button type="button" onClick={handleClose} className="btn-secondary">
                      Cancel
                    </button>
                    <button
                      type="submit"
                      className="btn-primary"
                      disabled={mutation.isPending}
                    >
                      {mutation.isPending ? (
                        <>
                          <span className="h-4 w-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                          Starting scan…
                        </>
                      ) : (
                        'Start Scan'
                      )}
                    </button>
                  </div>
                </form>
              </Dialog.Panel>
            </Transition.Child>
          </div>
        </div>
      </Dialog>
    </Transition>
  )
}
