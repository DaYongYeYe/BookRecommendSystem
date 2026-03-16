import request, { setToken } from './request'

interface LoginPayload {
  username: string
  password: string
}

interface RegisterPayload {
  username: string
  email: string
  password: string
}

export function login(data: LoginPayload) {
  return request.post('/auth/login', data).then((res: any) => {
    if (res.token) {
      setToken(res.token)
    }
    return res
  })
}

export function register(data: RegisterPayload) {
  return request.post('/auth/register', data)
}

export function checkAuth() {
  return request.get('/auth/check')
}

