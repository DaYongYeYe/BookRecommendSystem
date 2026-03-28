import request from '@/api/request'

export interface HomeBookItem {
  id: number
  title: string
  subtitle?: string | null
  author?: string | null
  description?: string | null
  cover?: string | null
  score?: number | null
  rating?: number | null
  rating_count?: number
  recent_reads?: number
  category_id?: number | null
  rank?: number
  recommend_reason?: string | null
  home_recommendation_reason?: string | null
  search_keywords?: string | null
}

export interface HomeCategoryItem {
  id: number
  code: string
  name: string
  en_name?: string | null
  description?: string | null
  cover?: string | null
  is_highlighted?: boolean
}

export interface HomeTagItem {
  id: number
  code: string
  label: string
  book_count?: number
}

export interface HomeContinueReadingItem extends HomeBookItem {
  section_id?: string | null
  paragraph_id?: string | null
  section_title?: string | null
  scroll_percent?: number
  updated_at?: string | null
  resume_url?: string | null
}

export function getHotTags() {
  return request.get<any, { items: HomeTagItem[] }>('/api/tags/hot')
}

export function getHighlightedCategories() {
  return request.get<any, { items: HomeCategoryItem[] }>('/api/categories/highlighted')
}

export function getHomeRecommendations(limit = 8) {
  return request.get<any, { items: HomeBookItem[] }>('/api/recommendations/personalized', {
    params: { limit },
  })
}

export function getContinueReading() {
  return request.get<any, { item: HomeContinueReadingItem | null }>('/api/home/continue-reading')
}

export function searchBooks(params: { q: string; limit?: number }) {
  return request.get<any, { query: string; items: HomeBookItem[] }>('/api/books/search', { params })
}

export function getBooksByCategoryOrTag(params: { category_id?: number; tag_id?: number }) {
  return request.get<any, { items: HomeBookItem[] }>('/api/books/by-category', { params })
}

export function getBookRankings(params?: { type?: string; limit?: number }) {
  return request.get<any, { type: string; items: HomeBookItem[] }>('/api/books/rankings', { params })
}

export function getMoreRecommendations(params: {
  page: number
  page_size: number
  category_id?: number
  tag_id?: number
}) {
  return request.get<any, { items: HomeBookItem[]; pagination: { page: number; page_size: number; total: number } }>(
    '/api/recommendations/more',
    { params }
  )
}
