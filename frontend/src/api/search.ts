import request from '@/api/request'
import type { HomeBookItem } from '@/api/home'

export interface SearchHotTermItem {
  keyword: string
  source?: string
}

export interface SearchHistoryItem {
  id?: number
  keyword: string
  search_count?: number
  last_searched_at?: string | null
}

export interface SearchBooksResponse {
  query: string
  total: number
  items: HomeBookItem[]
  recommended_items: HomeBookItem[]
}

export function getHotSearchTerms(limit = 8) {
  return request.get<any, { items: SearchHotTermItem[] }>('/api/search/hot-terms', {
    params: { limit },
  })
}

export function getSearchHistory(limit = 8) {
  return request.get<any, { items: SearchHistoryItem[] }>('/api/search/history', {
    params: { limit },
  })
}

export function clearSearchHistory() {
  return request.delete<any, { message: string }>('/api/search/history')
}

export function searchBooks(params: { q: string; limit?: number; recommend_limit?: number }) {
  return request.get<any, SearchBooksResponse>('/api/books/search', { params })
}
