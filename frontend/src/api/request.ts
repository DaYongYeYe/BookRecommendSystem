import axios, { AxiosError } from 'axios'
import router from '@/router'

const TOKEN_KEY = 'book_token'

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token)
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY)
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
      config.headers = config.headers || {}
      config.headers.Authorization = `Bearer ${token}`
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

    if (status === 401) {
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

