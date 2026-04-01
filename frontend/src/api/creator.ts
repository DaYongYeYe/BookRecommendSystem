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

export function getCreatorManuscripts(params?: { status?: string }) {
  return request.get<{ items: CreatorManuscriptItem[] }, { items: CreatorManuscriptItem[] }>('/creator/manuscripts', {
    params,
  })
}

export interface CreatorBookItem {
  id: number
  title: string
  author?: string | null
  status: string
  cover?: string | null
  description?: string | null
  word_count: number
  section_count?: number
  version_count?: number
  published_at?: string | null
}

export function getCreatorBooks() {
  return request.get<{ items: CreatorBookItem[] }, { items: CreatorBookItem[] }>('/creator/books')
}

export interface CreatorBookChapterItem {
  section_key?: string | null
  title: string
  content_text: string
  paragraph_ids?: string[]
  order_no?: number
}

export function getCreatorBookChapters(bookId: number) {
  return request.get<{ items: CreatorBookChapterItem[] }, { items: CreatorBookChapterItem[] }>(
    `/creator/books/${bookId}/chapters`
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
