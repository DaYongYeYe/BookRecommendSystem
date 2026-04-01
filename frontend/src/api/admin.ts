import request from './request'

export interface AdminLoginPayload {
  username: string
  password: string
  captcha_id: string
  captcha_code: string
}

export interface AdminLoginResponse {
  token?: string
}

export interface AdminRegisterPayload {
  username: string
  email: string
  password: string
  register_code: string
  captcha_id: string
  captcha_code: string
}

export interface AdminCaptchaResponse {
  captcha_id: string
  captcha_image: string
  expires_in: number
}

export interface AdminCreateUserPayload {
  username: string
  email: string
  password: string
  role: 'user' | 'admin' | 'creator' | 'editor'
  is_super_admin?: boolean
}

export interface AdminUpdateUserPayload {
  username?: string
  email?: string
  role?: 'user' | 'admin' | 'creator' | 'editor'
  is_super_admin?: boolean
}

export interface AdminUsersResponse {
  users: Array<{
    id: number
    username: string
    email: string
    role: 'user' | 'admin' | 'creator' | 'editor'
    is_super_admin?: boolean
    tenant_id?: number
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
  status: 'published' | 'draft' | 'archived'
  category_id?: number | null
  word_count?: number
  completion_status?: 'ongoing' | 'completed' | 'paused' | string
  suitable_audience?: string | null
  category_name?: string | null
  tags?: Array<{ id: number; label: string }>
  tag_ids?: number[]
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
  status?: 'published' | 'draft' | 'archived'
  category_id?: number | null
  word_count?: number
  completion_status?: 'ongoing' | 'completed' | 'paused'
  suitable_audience?: string
  tag_ids?: number[]
}

export interface AdminUpdateBookPayload extends Partial<AdminCreateBookPayload> {}

export interface AdminBookOptionsResponse {
  categories: Array<{ id: number; name: string }>
  tags: Array<{ id: number; label: string }>
  statuses: Array<{ value: 'published' | 'draft' | 'archived'; label: string }>
  completion_statuses?: Array<{ value: 'ongoing' | 'completed' | 'paused' | string; label: string }>
}

export interface AdminBatchUpdateBooksPayload {
  book_ids: number[]
  changes: {
    status?: 'published' | 'draft' | 'archived'
    category_id?: number | null
    is_featured?: boolean
    tag_ids?: number[]
  }
}

export interface AdminManuscriptItem {
  id: number
  book_id: number
  creator_id: number
  title: string
  cover?: string | null
  description?: string | null
  content_text?: string | null
  chapters?: Array<{
    section_key?: string | null
    title: string
    content_text: string
  }>
  status: 'draft' | 'submitted' | 'approved' | 'rejected' | 'published'
  review_comment?: string | null
  submitted_at?: string | null
  reviewed_at?: string | null
  reviewed_by?: number | null
  published_at?: string | null
  created_at?: string | null
  updated_at?: string | null
}

export type AdminCommentType = 'book' | 'highlight'

export interface AdminCommentItem {
  id: number
  type: AdminCommentType
  book_id?: number | null
  book_title?: string | null
  highlight_id?: number | null
  author: string
  content: string
  is_violation?: boolean
  violation_reason?: string | null
  moderated_at?: string | null
  created_at?: string | null
}

export interface AdminCommentsResponse {
  items: AdminCommentItem[]
  pagination?: {
    total: number
    page: number
    page_size: number
    pages: number
  }
}

export interface AdminDashboardOverviewResponse {
  cards: {
    pending_manuscripts: number
    today_new_users: number
    violation_comments_total: number
    today_violation_comments: number
    today_published_books: number
    total_users: number
  }
  trend: {
    dates: string[]
    series: Array<{
      date: string
      published_books: number
      new_users: number
    }>
  }
}

export function adminLogin(data: AdminLoginPayload) {
  return request.post<AdminLoginResponse, AdminLoginResponse>('/admin/auth/login', data)
}

export function adminRegister(data: AdminRegisterPayload) {
  return request.post('/admin/auth/register', data)
}

export function getAdminCaptcha() {
  return request.get<AdminCaptchaResponse, AdminCaptchaResponse>('/admin/auth/captcha')
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

export function getAdminBookOptions() {
  return request.get<AdminBookOptionsResponse, AdminBookOptionsResponse>('/admin/books/options')
}

export function batchUpdateAdminBooks(data: AdminBatchUpdateBooksPayload) {
  return request.post('/admin/books/batch', data)
}

export function uploadAdminBookCover(file: File) {
  const formData = new FormData()
  formData.append('cover', file)
  return request.post<any, { cover: string }>('/admin/books/cover/upload', formData)
}

export function getAdminManuscripts(params?: { status?: string; creator_id?: number }) {
  return request.get<{ items: AdminManuscriptItem[] }, { items: AdminManuscriptItem[] }>('/admin/manuscripts', {
    params,
  })
}

export function reviewAdminManuscript(
  manuscriptId: number,
  data: { action: 'approve' | 'reject'; review_comment?: string }
) {
  return request.post(`/admin/manuscripts/${manuscriptId}/review`, data)
}

export function publishAdminManuscript(manuscriptId: number) {
  return request.post(`/admin/manuscripts/${manuscriptId}/publish`)
}

export function getAdminComments(params: { page: number; page_size: number; keyword?: string; type?: string }) {
  return request.get<AdminCommentsResponse, AdminCommentsResponse>('/admin/comments', { params })
}

export function deleteAdminComment(commentType: AdminCommentType, commentId: number) {
  return request.delete(`/admin/comments/${commentType}/${commentId}`)
}

export function setAdminCommentViolation(
  commentType: AdminCommentType,
  commentId: number,
  data: { is_violation: boolean; violation_reason?: string }
) {
  return request.post(`/admin/comments/${commentType}/${commentId}/violation`, data)
}

export function getAdminDashboardOverview() {
  return request.get<AdminDashboardOverviewResponse, AdminDashboardOverviewResponse>('/admin/dashboard/overview')
}
