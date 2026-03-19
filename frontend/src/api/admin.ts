import request from './request'

export interface AdminLoginPayload {
  username: string
  password: string
}

export interface AdminLoginResponse {
  token?: string
}

export interface AdminRegisterPayload {
  username: string
  email: string
  password: string
  register_code: string
}

export interface AdminCreateUserPayload {
  username: string
  email: string
  password: string
  role: 'user' | 'admin'
}

export interface AdminUpdateUserPayload {
  username?: string
  email?: string
  role?: 'user' | 'admin'
}

export interface AdminUsersResponse {
  users: Array<{
    id: number
    username: string
    email: string
    role: 'user' | 'admin'
  }>
  pagination?: {
    total: number
    page: number
    page_size: number
    pages: number
  }
}

export interface AdminBookItem {
  id: number
  title: string
  subtitle?: string | null
  author?: string | null
  description?: string | null
  cover?: string | null
  score?: number | null
  rating?: number | null
  rating_count: number
  recent_reads: number
  is_featured: boolean
  category_id?: number | null
}

export interface AdminBooksResponse {
  books: AdminBookItem[]
  pagination?: {
    total: number
    page: number
    page_size: number
    pages: number
  }
}

export interface AdminCreateBookPayload {
  title: string
  subtitle?: string
  author?: string
  description?: string
  cover?: string
  score?: number | null
  rating?: number | null
  rating_count?: number
  recent_reads?: number
  is_featured?: boolean
  category_id?: number | null
}

export interface AdminUpdateBookPayload extends Partial<AdminCreateBookPayload> {}

export function adminLogin(data: AdminLoginPayload) {
  return request.post<AdminLoginResponse, AdminLoginResponse>('/admin/auth/login', data)
}

export function adminRegister(data: AdminRegisterPayload) {
  return request.post('/admin/auth/register', data)
}

export function getAdminUsers(params: { page: number; page_size: number; keyword?: string }) {
  return request.get<AdminUsersResponse, AdminUsersResponse>('/admin/users', { params })
}

export function createAdminUser(data: AdminCreateUserPayload) {
  return request.post('/admin/users', data)
}

export function updateAdminUser(userId: number, data: AdminUpdateUserPayload) {
  return request.put(`/admin/users/${userId}`, data)
}

export function deleteAdminUser(userId: number) {
  return request.delete(`/admin/users/${userId}`)
}

export function resetAdminUserPassword(userId: number, new_password: string) {
  return request.post(`/admin/users/${userId}/reset_password`, { new_password })
}

export function getAdminBooks(params: { page: number; page_size: number; keyword?: string }) {
  return request.get<AdminBooksResponse, AdminBooksResponse>('/admin/books', { params })
}

export function createAdminBook(data: AdminCreateBookPayload) {
  return request.post('/admin/books', data)
}

export function updateAdminBook(bookId: number, data: AdminUpdateBookPayload) {
  return request.put(`/admin/books/${bookId}`, data)
}

export function deleteAdminBook(bookId: number) {
  return request.delete(`/admin/books/${bookId}`)
}
