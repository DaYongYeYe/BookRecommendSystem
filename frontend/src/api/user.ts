import request from '@/api/request'

export interface UserProfile {
  id: number
  username: string
  name: string | null
  pen_name: string | null
  email: string
  avatar_url: string | null
  age: number | null
  province: string | null
  city: string | null
  role: string
  is_creator: boolean
  creator_profile?: {
    status: string
    activated_at?: string | null
    deactivated_at?: string | null
  } | null
}

export interface BookItem {
  id: number
  title: string
  subtitle?: string
  author?: string
  cover?: string
  rating?: number
  favorited_at?: string | null
  history?: {
    section_id: string | null
    paragraph_id: string | null
    scroll_percent: number
    updated_at: string | null
  }
}

export interface ReadingStatsPayload {
  week_start: string
  stats: {
    weekly_read_minutes: number
    weekly_reading_days: number
    completed_chapter_count: number
    shelf_count: number
    highlight_count: number
    comment_count: number
    bookmark_count: number
    reading_streak_days: number
  }
  preferences: {
    theme: 'light' | 'dark' | 'green' | 'parchment'
    font_size: number
    line_height: number
    margin: 'narrow' | 'medium' | 'wide'
    show_highlights: boolean
    show_comments: boolean
    updated_at?: string | null
  }
  achievements: Array<{
    achievement_key: string
    title: string
    description: string
    unlocked: boolean
    unlocked_at?: string | null
  }>
  recent_books: Array<{
    id: number
    title: string
    author?: string | null
    cover?: string | null
    section_id?: string | null
    scroll_percent: number
    updated_at?: string | null
  }>
}

export function getUserProfile() {
  return request.get<any, { user: UserProfile }>('/user/profile')
}

export function updateUserProfile(payload: {
  name?: string
  pen_name?: string
  avatar_url?: string
  age?: number | null
  email?: string
  province?: string
  city?: string
}) {
  return request.put<any, { user: UserProfile }>('/user/profile', payload)
}

export function uploadUserAvatar(file: File) {
  const formData = new FormData()
  formData.append('avatar', file)
  return request.post<any, { avatar_url: string; user: UserProfile }>('/user/avatar/upload', formData)
}

export function getUserFavorites() {
  return request.get<any, { items: BookItem[] }>('/user/favorites')
}

export function getUserHistory() {
  return request.get<any, { items: BookItem[] }>('/user/history')
}

export function getReadingStats() {
  return request.get<any, ReadingStatsPayload>('/user/reading-stats')
}
