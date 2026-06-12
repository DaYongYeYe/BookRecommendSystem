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
  role: 'user' | 'admin' | 'editor'
  is_super_admin?: boolean
  is_creator?: boolean
}

export interface AdminUpdateUserPayload {
  username?: string
  email?: string
  role?: 'user' | 'admin' | 'editor'
  is_super_admin?: boolean
  is_creator?: boolean
}

export interface AdminUsersResponse {
  users: Array<{
    id: number
    username: string
    email: string
    role: 'user' | 'admin' | 'editor'
    is_creator?: boolean
    creator_profile?: {
      status: string
      activated_at?: string | null
      deactivated_at?: string | null
    } | null
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

export interface AdminListPagination {
  total: number
  page: number
  page_size: number
  pages?: number
}

export interface AdminManuscriptsResponse {
  items: AdminManuscriptItem[]
  pagination?: AdminListPagination
}

export interface AdminWorkReviewItem {
  id: number
  title: string
  subtitle?: string | null
  author?: string | null
  description?: string | null
  cover?: string | null
  category_id?: number | null
  category_name?: string | null
  category_code?: string | null
  subcategory_code?: string | null
  tags?: Array<{ id: number; code?: string; label: string }>
  tag_ids?: number[]
  completion_status?: string
  price_type?: string
  creation_type?: string
  audit_status: 'draft' | 'pending' | 'approved' | 'rejected' | string
  audit_comment?: string | null
  audit_submitted_at?: string | null
  shelf_status?: 'up' | 'down' | 'forced_down' | string
  status?: string
  creator_id?: number | null
  created_at?: string | null
  updated_at?: string | null
}

export interface AdminWorkReviewsResponse {
  items: AdminWorkReviewItem[]
  pagination?: AdminListPagination
}

export interface AdminChapterReviewItem {
  chapter: {
    id: number
    book_id: number
    chapter_key: string
    chapter_no: number
    title: string
    status: string
    published_revision_id?: number | null
    updated_at?: string | null
  }
  book: {
    id: number
    title: string
    shelf_status?: string
    audit_status?: string
  }
  latest_revision: {
    id: number
    chapter_id: number
    version_no: number
    title: string
    content_text: string
    status: 'pending' | 'rejected' | 'published' | string
    review_comment?: string | null
    submitted_at?: string | null
    reviewed_at?: string | null
    published_at?: string | null
    updated_at?: string | null
  }
}

export interface AdminChapterReviewsResponse {
  items: AdminChapterReviewItem[]
  pagination?: AdminListPagination
}

export interface AdminChapterCompareResponse {
  chapter: AdminChapterReviewItem['chapter']
  book: AdminChapterReviewItem['book']
  latest_revision: AdminChapterReviewItem['latest_revision'] | null
  published_revision: AdminChapterReviewItem['latest_revision'] | null
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

export interface AdminCreatorApplicationItem {
  id: number
  user_id: number
  tenant_id: number
  status: 'pending' | 'approved' | 'rejected' | string
  apply_reason?: string | null
  review_comment?: string | null
  reviewed_by?: number | null
  reviewed_by_name?: string | null
  username?: string | null
  email?: string | null
  current_role?: string | null
  is_creator?: boolean
  created_at?: string | null
  reviewed_at?: string | null
}

export interface AdminCreatorApplicationsResponse {
  items: AdminCreatorApplicationItem[]
  pagination?: AdminListPagination
}

export interface AdminRecommendationPlacementItem {
  id: number
  code: string
  name: string
  description?: string | null
  scene: string
  strategy: string
  max_items: number
  is_active: boolean
  sort_order: number
  created_at?: string | null
  updated_at?: string | null
}

export interface AdminRecommendationPlacementsResponse {
  items: AdminRecommendationPlacementItem[]
  pagination?: AdminListPagination
}

export interface AdminRankingConfigItem {
  id: number
  type: string
  rank_no: number
  book_id: number
  snapshot_date: string
  book?: {
    id: number
    title: string
    author?: string | null
    cover?: string | null
    status?: string
    shelf_status?: string
  }
}

export interface AdminRankingTypeOption {
  key: string
  label: string
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

export function getAdminManuscripts(params?: { page?: number; page_size?: number; status?: string; creator_id?: number }) {
  return request.get<AdminManuscriptsResponse, AdminManuscriptsResponse>('/admin/manuscripts', {
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

export function getAdminWorkReviews(params?: { page?: number; page_size?: number; audit_status?: string; shelf_status?: string; keyword?: string }) {
  return request.get<AdminWorkReviewsResponse, AdminWorkReviewsResponse>('/admin/works/reviews', {
    params,
  })
}

export function reviewAdminWork(bookId: number, data: { action: 'approve' | 'reject'; audit_comment?: string }) {
  return request.post(`/admin/works/${bookId}/review`, data)
}

export function getAdminChapterReviews(params?: { page?: number; page_size?: number; status?: 'pending' | 'rejected'; keyword?: string }) {
  return request.get<AdminChapterReviewsResponse, AdminChapterReviewsResponse>('/admin/chapters/reviews', {
    params,
  })
}

export function reviewAdminChapter(chapterId: number, data: { action: 'approve' | 'reject'; review_comment?: string }) {
  return request.post(`/admin/chapters/${chapterId}/review`, data)
}

export function batchReviewAdminChapters(data: { chapter_ids: number[]; action: 'approve' | 'reject'; review_comment?: string }) {
  return request.post<
    {
      message: string
      action: 'approve' | 'reject'
      success_count: number
      failed_count: number
      failed_items: Array<{ chapter_id: number; error: string }>
    },
    {
      message: string
      action: 'approve' | 'reject'
      success_count: number
      failed_count: number
      failed_items: Array<{ chapter_id: number; error: string }>
    }
  >('/admin/chapters/review/batch', data)
}

export function getAdminChapterCompare(chapterId: number) {
  return request.get<AdminChapterCompareResponse, AdminChapterCompareResponse>(`/admin/chapters/${chapterId}/compare`)
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

export function getAdminCreatorApplications(params?: { page?: number; page_size?: number; status?: string; keyword?: string }) {
  return request.get<AdminCreatorApplicationsResponse, AdminCreatorApplicationsResponse>('/admin/creator-applications', {
    params,
  })
}

export function reviewAdminCreatorApplication(
  applicationId: number,
  data: { action: 'approve' | 'reject'; review_comment?: string }
) {
  return request.post(`/admin/creator-applications/${applicationId}/review`, data)
}

export function getAdminRecommendationPlacements(params?: { page?: number; page_size?: number; scene?: string }) {
  return request.get<AdminRecommendationPlacementsResponse, AdminRecommendationPlacementsResponse>(
    '/admin/recommendation-placements',
    { params }
  )
}

export function createAdminRecommendationPlacement(data: Omit<AdminRecommendationPlacementItem, 'id' | 'created_at' | 'updated_at'>) {
  return request.post<{ item: AdminRecommendationPlacementItem }, { item: AdminRecommendationPlacementItem }>(
    '/admin/recommendation-placements',
    data
  )
}

export function updateAdminRecommendationPlacement(
  placementId: number,
  data: Partial<Omit<AdminRecommendationPlacementItem, 'id' | 'created_at' | 'updated_at'>>
) {
  return request.put<{ item: AdminRecommendationPlacementItem }, { item: AdminRecommendationPlacementItem }>(
    `/admin/recommendation-placements/${placementId}`,
    data
  )
}

export function deleteAdminRecommendationPlacement(placementId: number) {
  return request.delete(`/admin/recommendation-placements/${placementId}`)
}

export function getAdminRankingConfigs(params: { type: string; snapshot_date: string }) {
  return request.get<
    { type: string; snapshot_date: string; available_types: AdminRankingTypeOption[]; items: AdminRankingConfigItem[] },
    { type: string; snapshot_date: string; available_types: AdminRankingTypeOption[]; items: AdminRankingConfigItem[] }
  >('/admin/ranking-configs', { params })
}

export function saveAdminRankingConfig(data: { type: string; snapshot_date: string; book_ids: number[] }) {
  return request.post<
    { type: string; snapshot_date: string; items: AdminRankingConfigItem[] },
    { type: string; snapshot_date: string; items: AdminRankingConfigItem[] }
  >('/admin/ranking-configs', data)
}
