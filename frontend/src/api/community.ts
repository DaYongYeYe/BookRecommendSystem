import request from '@/api/request'
import type { HomeBookItem, HomeTagItem } from '@/api/home'

export interface CommunityUser {
  id: number
  nickname: string
  avatar?: string | null
}

export interface CommunityBookCard {
  id: number
  title: string
  author?: string | null
  cover?: string | null
  rating?: number | null
  category_id?: number | null
  note?: string | null
  sort_order?: number
}

export interface CommunityBookList {
  id: number
  user_id: number
  title: string
  description?: string | null
  visibility: 'public' | 'private' | string
  cover?: string | null
  likes_count: number
  book_count: number
  books: CommunityBookCard[]
  user: CommunityUser
  created_at?: string | null
  updated_at?: string | null
}

export interface CommunityReview {
  id: number
  user_id: number
  book_id: number
  title: string
  content: string
  rating?: number | null
  likes_count: number
  comments_count: number
  liked_by_me?: boolean
  user: CommunityUser
  book?: CommunityBookCard | null
  created_at?: string | null
}

export interface InterestTag extends HomeTagItem {
  weight: number
  source_summary?: string | null
}

export function getCommunityBooklists(params?: { limit?: number; q?: string }) {
  return request.get<any, { items: CommunityBookList[] }>('/api/community/booklists', { params })
}

export function createCommunityBooklist(payload: {
  title: string
  description?: string
  visibility?: 'public' | 'private'
}) {
  return request.post<any, { message: string; item: CommunityBookList }>('/api/community/booklists', payload)
}

export function addBookToCommunityBooklist(listId: number, payload: { book_id: number; note?: string }) {
  return request.post<any, { message: string; item: CommunityBookList }>(`/api/community/booklists/${listId}/books`, payload)
}

export function getCommunityReviews(params?: { limit?: number; book_id?: number }) {
  return request.get<any, { items: CommunityReview[] }>('/api/community/reviews', { params })
}

export function createCommunityReview(payload: {
  book_id: number
  title: string
  content: string
  rating?: number
  visibility?: 'public' | 'private'
}) {
  return request.post<any, { message: string; item: CommunityReview }>('/api/community/reviews', payload)
}

export function reactCommunityReview(reviewId: number, liked: boolean) {
  return request.post<any, { message: string; item: CommunityReview }>(`/api/community/reviews/${reviewId}/reaction`, { liked })
}

export function getInterestTags(limit = 10) {
  return request.get<any, { items: InterestTag[]; generated_from: string }>('/api/recommendations/interest-tags', {
    params: { limit },
  })
}

export type CommunityCandidateBook = HomeBookItem
