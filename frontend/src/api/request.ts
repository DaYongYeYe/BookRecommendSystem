import axios, { AxiosError } from 'axios'
import router from '@/router'

type TokenScope = 'user' | 'admin'

const USER_TOKEN_KEY = 'book_token_user'
const ADMIN_TOKEN_KEY = 'book_token_admin'
const LEGACY_TOKEN_KEYS = ['token', 'access_token', 'book_admin_token']

function resolveCurrentPath(): string {
  const routePath = router.currentRoute.value.path
  if (routePath) return routePath
  if (typeof window !== 'undefined') return window.location.pathname || ''
  return ''
}

function resolveScope(path = resolveCurrentPath()): TokenScope {
  return path.startsWith('/manage') ? 'admin' : 'user'
}

function getScopeTokenKey(scope: TokenScope): string {
  return scope === 'admin' ? ADMIN_TOKEN_KEY : USER_TOKEN_KEY
}

function normalizeToken(rawToken: string | null | undefined): string | null {
  const trimmed = rawToken?.trim()
  if (!trimmed) return null
  // Compatibility: tolerate persisted values like "Bearer xxx".
  return trimmed.startsWith('Bearer ') ? trimmed.slice(7).trim() || null : trimmed
}

export function getToken(scope: TokenScope = resolveScope()): string | null {
  const tokenKey = getScopeTokenKey(scope)
  const token = normalizeToken(localStorage.getItem(tokenKey))
  if (token) {
    if (token !== localStorage.getItem(tokenKey)) {
      localStorage.setItem(tokenKey, token)
    }
    return token
  }

  // Backward compatibility: migrate legacy token keys to scoped token key.
  for (const legacyKey of LEGACY_TOKEN_KEYS) {
    const legacyToken = normalizeToken(localStorage.getItem(legacyKey))
    if (legacyToken) {
      localStorage.setItem(tokenKey, legacyToken)
      return legacyToken
    }
  }
  const legacySharedToken = normalizeToken(localStorage.getItem('book_token'))
  if (legacySharedToken) {
    localStorage.setItem(tokenKey, legacySharedToken)
    localStorage.removeItem('book_token')
    return legacySharedToken
  }
  return null
}

export function setToken(token: string, scope: TokenScope = resolveScope()) {
  const normalizedToken = normalizeToken(token)
  if (!normalizedToken) return
  localStorage.setItem(getScopeTokenKey(scope), normalizedToken)
  localStorage.removeItem('book_token')
  for (const legacyKey of LEGACY_TOKEN_KEYS) {
    localStorage.removeItem(legacyKey)
  }
}

export function clearToken(scope: TokenScope | 'all' = resolveScope()) {
  if (scope === 'all') {
    localStorage.removeItem(USER_TOKEN_KEY)
    localStorage.removeItem(ADMIN_TOKEN_KEY)
  } else {
    localStorage.removeItem(getScopeTokenKey(scope))
  }
  localStorage.removeItem('book_token')
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
let isCreatorForbiddenRedirecting = false

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

    const requestUrl = `${error.config?.url || ''}`.toLowerCase()
    const isCreatorApi = requestUrl.startsWith('/creator/')
    if (status === 403 && sentAuthHeader && isCreatorApi) {
      if (!isCreatorForbiddenRedirecting) {
        isCreatorForbiddenRedirecting = true
        router
          .push({
            path: '/creator-center',
            query: { redirect: router.currentRoute.value.fullPath },
          })
          .finally(() => {
            isCreatorForbiddenRedirecting = false
          })
      }
    }

    return Promise.reject(error)
  }
)

export default request

