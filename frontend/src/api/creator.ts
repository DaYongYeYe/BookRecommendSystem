import request from './request'

export interface CreatorManuscriptItem {
  id: number
  book_id: number
  creator_id: number
  title: string
  cover?: string | null
  description?: string | null
  content_text?: string | null
  chapters?: CreatorBookChapterItem[]
  update_mode: 'create' | 'full' | 'append'
  status: 'draft' | 'submitted' | 'approved' | 'rejected' | 'published'
  review_comment?: string | null
  submitted_at?: string | null
  reviewed_at?: string | null
  reviewed_by?: number | null
  published_at?: string | null
  created_at?: string | null
  updated_at?: string | null
}

export function getCreatorManuscripts(params?: { status?: string; recycle?: boolean }) {
  return request.get<{ items: CreatorManuscriptItem[] }, { items: CreatorManuscriptItem[] }>('/creator/manuscripts', {
    params,
  })
}

export interface CreatorApplicationItem {
  id: number
  user_id: number
  tenant_id: number
  status: 'pending' | 'approved' | 'rejected' | string
  apply_reason?: string | null
  review_comment?: string | null
  reviewed_by?: number | null
  reviewed_by_name?: string | null
  created_at?: string | null
  reviewed_at?: string | null
}

export function getCreatorApplication() {
  return request.get<
    { application: CreatorApplicationItem | null; can_apply: boolean; already_creator: boolean },
    { application: CreatorApplicationItem | null; can_apply: boolean; already_creator: boolean }
  >('/creator/application')
}

export function submitCreatorApplication(data: { apply_reason: string }) {
  return request.post<{ application: CreatorApplicationItem }, { application: CreatorApplicationItem }>('/creator/application', data)
}

export interface CreatorBookItem {
  id: number
  title: string
  subtitle?: string | null
  author?: string | null
  status: string
  cover?: string | null
  description?: string | null
  category_id?: number | null
  subcategory_code?: string | null
  audit_status?: string
  shelf_status?: string
  price_type?: string
  creation_type?: string
  tags?: Array<{ id: number; code?: string; label: string }>
  tag_ids?: number[]
  word_count: number
  section_count?: number
  version_count?: number
  created_at?: string | null
  updated_at?: string | null
  published_at?: string | null
}

export function getCreatorBooks() {
  return request.get<{ items: CreatorBookItem[] }, { items: CreatorBookItem[] }>('/creator/books')
}

export interface CreatorWorkTagItem {
  id: number
  code: string
  label: string
  is_hot?: boolean
}

export interface CreatorWorkCategoryItem {
  id: number
  code: string
  name: string
  subcategories: Array<{ code: string; name: string }>
  tag_candidates: CreatorWorkTagItem[]
}

export interface CreatorWorkItem extends CreatorBookItem {
  category_name?: string | null
  category_code?: string | null
  subcategories?: Array<{ code: string; name: string }>
  completion_status?: 'ongoing' | 'paused' | 'completed' | string
  protagonist?: string | null
  worldview?: string | null
  author_message?: string | null
  author_notice?: string | null
  copyright_notice?: string | null
  update_note?: string | null
  audit_comment?: string | null
  audit_submitted_at?: string | null
  off_shelf_reason?: string | null
  ready_for_audit?: boolean
  ready_for_publish?: boolean
}

export interface CreatorWorkOptionsResponse {
  categories: CreatorWorkCategoryItem[]
  rules: {
    description_min_length: number
    tag_min_count: number
    tag_max_count: number
    cover_formats: string[]
    cover_max_size: number
    cover_ratio_hint: string
  }
  enum_options: {
    audit_statuses: string[]
    shelf_statuses: string[]
    completion_statuses: string[]
    price_types: string[]
    creation_types: string[]
  }
}

export function getCreatorWorkOptions() {
  return request.get<CreatorWorkOptionsResponse, CreatorWorkOptionsResponse>('/creator/work-options')
}

export function getCreatorWorks(params?: {
  keyword?: string
  audit_status?: string
  shelf_status?: string
  completion_status?: string
  recycle?: boolean
}) {
  return request.get<{ items: CreatorWorkItem[]; summary: Record<string, number> }, { items: CreatorWorkItem[]; summary: Record<string, number> }>(
    '/creator/works',
    { params }
  )
}

export function getCreatorWorkDetail(bookId: number) {
  return request.get<{ item: CreatorWorkItem }, { item: CreatorWorkItem }>(`/creator/works/${bookId}`)
}

export function createCreatorWork(data: FormData | Record<string, any>) {
  return request.post<{ item: CreatorWorkItem }, { item: CreatorWorkItem }>('/creator/works', data)
}

export function updateCreatorWork(bookId: number, data: FormData | Record<string, any>) {
  return request.put<{ item: CreatorWorkItem; re_audit_required?: boolean }, { item: CreatorWorkItem; re_audit_required?: boolean }>(
    `/creator/works/${bookId}`,
    data
  )
}

export function submitCreatorWorkAudit(bookId: number) {
  return request.post(`/creator/works/${bookId}/submit-audit`)
}

export function updateCreatorWorkShelf(bookId: number, data: { action: 'up' | 'down'; reason?: string }) {
  return request.post(`/creator/works/${bookId}/shelf`, data)
}

export function updateCreatorWorkCompletionStatus(
  bookId: number,
  data: { completion_status: 'ongoing' | 'paused' | 'completed'; confirm?: boolean }
) {
  return request.post(`/creator/works/${bookId}/completion-status`, data)
}

export function deleteCreatorWork(bookId: number) {
  return request.delete(`/creator/works/${bookId}`)
}

export function restoreCreatorWork(bookId: number) {
  return request.post(`/creator/works/${bookId}/restore`)
}

export interface CreatorBookChapterItem {
  id?: number
  section_key?: string | null
  title: string
  content_text: string
  paragraph_ids?: string[]
  order_no?: number
  status?: string
  latest_revision?: CreatorChapterRevisionItem | null
  published_revision?: CreatorChapterRevisionItem | null
  can_edit?: boolean
  can_submit?: boolean
}

export function getCreatorBookChapters(bookId: number) {
  return request.get<{ items: CreatorBookChapterItem[] }, { items: CreatorBookChapterItem[] }>(
    `/creator/books/${bookId}/chapters`
  )
}

export interface CreatorChapterRevisionItem {
  id: number
  chapter_id: number
  version_no: number
  title: string
  content_text: string
  summary?: string | null
  status: string
  review_comment?: string | null
  submitted_at?: string | null
  reviewed_at?: string | null
  reviewed_by?: number | null
  published_at?: string | null
  created_by?: number | null
  created_at?: string | null
  updated_at?: string | null
}

export function createCreatorBookChapter(bookId: number, data: { title: string; content_text: string }) {
  return request.post<
    { message: string; chapter: CreatorBookChapterItem; revision: CreatorChapterRevisionItem },
    { message: string; chapter: CreatorBookChapterItem; revision: CreatorChapterRevisionItem }
  >(`/creator/books/${bookId}/chapters`, data)
}

export function updateCreatorBookChapter(bookId: number, chapterId: number, data: { title: string; content_text: string }) {
  return request.put<
    { message: string; chapter: CreatorBookChapterItem; revision: CreatorChapterRevisionItem },
    { message: string; chapter: CreatorBookChapterItem; revision: CreatorChapterRevisionItem }
  >(`/creator/books/${bookId}/chapters/${chapterId}`, data)
}

export function submitCreatorBookChapter(bookId: number, chapterId: number) {
  return request.post<
    { message: string; chapter: CreatorBookChapterItem; revision: CreatorChapterRevisionItem },
    { message: string; chapter: CreatorBookChapterItem; revision: CreatorChapterRevisionItem }
  >(`/creator/books/${bookId}/chapters/${chapterId}/submit`)
}

export function getCreatorBookChapterVersions(bookId: number, chapterId: number) {
  return request.get<{ items: CreatorChapterRevisionItem[] }, { items: CreatorChapterRevisionItem[] }>(
    `/creator/books/${bookId}/chapters/${chapterId}/versions`
  )
}

export function reorderCreatorBookChapters(bookId: number, chapterIds: number[]) {
  return request.post<{ message: string; items: CreatorBookChapterItem[] }, { message: string; items: CreatorBookChapterItem[] }>(
    `/creator/books/${bookId}/chapters/reorder`,
    { chapter_ids: chapterIds }
  )
}

export function createCreatorManuscript(data: FormData | Record<string, any>) {
  return request.post('/creator/manuscripts', data)
}

export function updateCreatorManuscript(manuscriptId: number, data: FormData | Record<string, any>) {
  return request.put(`/creator/manuscripts/${manuscriptId}`, data)
}

export function submitCreatorManuscript(manuscriptId: number) {
  return request.post(`/creator/manuscripts/${manuscriptId}/submit`)
}

export function deleteCreatorManuscript(manuscriptId: number) {
  return request.delete(`/creator/manuscripts/${manuscriptId}`)
}

export function restoreCreatorManuscript(manuscriptId: number) {
  return request.post(`/creator/manuscripts/${manuscriptId}/restore`)
}

export interface CreatorBookDistributionItem {
  label: string
  count: number
  percent: number
}

export interface CreatorBookAnalyticsItem {
  book_id: number
  title: string
  status: string
  metrics: {
    impressions: number
    reads: number
    read_users: number
    avg_read_duration_seconds: number
    avg_read_duration_label: string
  }
  geo_distribution: CreatorBookDistributionItem[]
  age_distribution: CreatorBookDistributionItem[]
}

export function getCreatorBookAnalytics(params?: { limit?: number }) {
  return request.get<{ items: CreatorBookAnalyticsItem[] }, { items: CreatorBookAnalyticsItem[] }>(
    '/creator/books/analytics',
    { params }
  )
}
