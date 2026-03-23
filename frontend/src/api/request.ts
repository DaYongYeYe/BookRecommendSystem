import axios, { AxiosError } from 'axios'
import router from '@/router'

const TOKEN_KEY = 'book_token'
const LEGACY_TOKEN_KEYS = ['token', 'access_token', 'book_admin_token']

function normalizeToken(rawToken: string | null | undefined): string | null {
  const trimmed = rawToken?.trim()
  if (!trimmed) return null
  // Compatibility: tolerate persisted values like "Bearer xxx".
  return trimmed.startsWith('Bearer ') ? trimmed.slice(7).trim() || null : trimmed
}

export function getToken(): string | null {
  const token = normalizeToken(localStorage.getItem(TOKEN_KEY))
  if (token) {
    if (token !== localStorage.getItem(TOKEN_KEY)) {
      localStorage.setItem(TOKEN_KEY, token)
    }
    return token
  }

  // Backward compatibility: migrate legacy token keys to book_token.
  for (const legacyKey of LEGACY_TOKEN_KEYS) {
    const legacyToken = normalizeToken(localStorage.getItem(legacyKey))
    if (legacyToken) {
      localStorage.setItem(TOKEN_KEY, legacyToken)
      return legacyToken
    }
  }
  return null
}

export function setToken(token: string) {
  const normalizedToken = normalizeToken(token)
  if (!normalizedToken) return
  localStorage.setItem(TOKEN_KEY, normalizedToken)
  for (const legacyKey of LEGACY_TOKEN_KEYS) {
    localStorage.removeItem(legacyKey)
  }
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY)
  for (const legacyKey of LEGACY_TOKEN_KEYS) {
    localStorage.removeItem(legacyKey)
  }
}

const request = axios.create({
  // In local dev, prefer same-origin requests so Vite proxy can avoid CORS.
  baseURL: import.meta.env.VITE_API_BASE_URL || '',
  timeout: 10000,
})

request.interceptors.request.use(
  (config) => {
    const token = getToken()
    if (token) {
      // Axios v1 may use AxiosHeaders; use set() when available.
      if (config.headers && typeof (config.headers as any).set === 'function') {
        ;(config.headers as any).set('Authorization', `Bearer ${token}`)
      } else {
        config.headers = {
          ...(config.headers || {}),
          Authorization: `Bearer ${token}`,
        } as any
      }
    }
    return config
  },
  (error) => Promise.reject(error)
)

let isRedirecting = false

request.interceptors.response.use(
  (response) => response.data,
  (error: AxiosError<any>) => {
    const status = error.response?.status
    const headers = error.config?.headers as any
    const sentAuthHeader =
      typeof headers?.get === 'function'
        ? Boolean(headers.get('Authorization'))
        : Boolean(headers?.Authorization || headers?.authorization)

    if (status === 401 && sentAuthHeader) {
      clearToken()
      if (!isRedirecting) {
        isRedirecting = true
        const isAdminPage = router.currentRoute.value.path.startsWith('/manage')
        const loginPath = isAdminPage ? '/manage/login' : '/login'
        router
          .push({
            path: loginPath,
            query: { redirect: router.currentRoute.value.fullPath },
          })
          .finally(() => {
            isRedirecting = false
          })
      }
    }

    return Promise.reject(error)
  }
)

export default request

