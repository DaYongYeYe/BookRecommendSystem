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
  email_code: string
}

export interface SendEmailCodePayload {
  email: string
  purpose: 'register' | 'reset_password'
  captcha_id: string
  captcha_code: string
}

export interface PasswordResetPayload {
  email: string
  email_code: string
  password: string
}

export interface CaptchaResponse {
  captcha_id: string
  captcha_image: string
  expires_in: number
}

export interface EmailCodeResponse {
  message: string
  masked_email: string
  expires_in: number
  resend_seconds: number
}

export function login(data: LoginPayload) {
  return request.post('/auth/login', data).then((res: any) => {
    if (res.token) {
      setToken(res.token, 'user')
    }
    return res
  })
}

export function register(data: RegisterPayload) {
  return request.post('/auth/register', data)
}

export function sendEmailCode(data: SendEmailCodePayload) {
  return request.post<EmailCodeResponse, EmailCodeResponse>('/auth/email-code', data)
}

export function resetPassword(data: PasswordResetPayload) {
  return request.post('/auth/password-reset', data)
}

export function getCaptcha() {
  return request.get<CaptchaResponse, CaptchaResponse>('/auth/captcha')
}

export function checkAuth() {
  return request.get('/auth/check')
}
