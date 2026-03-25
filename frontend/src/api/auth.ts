import request, { setToken } from './request'

interface LoginPayload {
  username: string
  password: string
  captcha_id: string
  captcha_code: string
}

interface RegisterPayload {
  username: string
  email: string
  password: string
  age: number
  captcha_id: string
  captcha_code: string
}

export interface CaptchaResponse {
  captcha_id: string
  captcha_image: string
  expires_in: number
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

export function getCaptcha() {
  return request.get<CaptchaResponse, CaptchaResponse>('/auth/captcha')
}

export function checkAuth() {
  return request.get('/auth/check')
}

