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
