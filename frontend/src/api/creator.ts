import request from './request'

export interface CreatorManuscriptItem {
  id: number
  book_id: number
  creator_id: number
  title: string
  cover?: string | null
  description?: string | null
  content_text?: string | null
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
