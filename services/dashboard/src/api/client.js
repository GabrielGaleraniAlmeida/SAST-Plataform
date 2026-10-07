/**
 * Axios client instance pre-configured with:
 * - Base URL from VITE_API_URL env variable (falls back to /api)
 * - JSON content type headers
 * - Request/response interceptors for error normalisation
 */
import axios from 'axios'

const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_URL ? `${import.meta.env.VITE_API_URL}/api/v1` : '/api/v1',
  headers: {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  },
  timeout: 30_000,
})

// ── Request interceptor ────────────────────────────────────────────────────
apiClient.interceptors.request.use(
  (config) => {
    // Attach auth token if available (e.g. from localStorage)
    const token = localStorage.getItem('sast_token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => Promise.reject(error),
)

// ── Response interceptor ───────────────────────────────────────────────────
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response) {
      // Normalise error message from backend detail field
      const message =
        error.response.data?.detail ||
        error.response.data?.message ||
        `HTTP ${error.response.status}: ${error.response.statusText}`
      error.displayMessage = message
    } else if (error.request) {
      error.displayMessage = 'Network error — cannot reach the API server.'
    } else {
      error.displayMessage = error.message
    }
    return Promise.reject(error)
  },
)

export default apiClient
