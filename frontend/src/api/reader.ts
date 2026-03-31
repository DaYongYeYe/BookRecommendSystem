import request from '@/api/request'

export interface ReaderComment {
  id: number
  author: string
  content: string
  created_at: string
}

export interface ReaderHighlight {
  id: number
  paragraph_id: string
  start_offset: number
  end_offset: number
  selected_text: string
  color: string
  note: string
  created_by: string
  created_at: string
  comments: ReaderComment[]
}

export interface ReaderParagraph {
  id: string
  text: string
}

export interface ReaderSection {
  id: string
  title: string
  summary: string
  paragraphs: ReaderParagraph[]
}

export interface ReaderOutlineItem {
  id: string
  title: string
  level: number
}

export interface ReaderBook {
  id: number
  title: string
  subtitle: string
  author: string
  cover: string
  description: string
  progress_percent: number
  total_words: number
  rating?: number
  rating_count?: number
  recent_reads?: number
  category?: {
    id: number
    code: string
    name: string
    en_name?: string | null
    description?: string | null
    cover?: string | null
    is_highlighted?: boolean
  } | null
  tags?: Array<{ id: number; code?: string | null; label: string }>
  word_count?: number
  estimated_reading_minutes?: number
  completion_status?: 'ongoing' | 'completed' | 'paused' | string
  suitable_audience?: string
  recommendation_reason?: string
  keyword_tags?: string[]
  in_shelf?: boolean
  decision_points?: string[]
}

export interface ReaderPayload {
  book: ReaderBook
  outline: ReaderOutlineItem[]
  sections: ReaderSection[]
  highlights: ReaderHighlight[]
  book_comments: ReaderComment[]
}

export interface BookLandingPayload {
  book: ReaderBook
  outline: ReaderOutlineItem[]
  book_comments: ReaderComment[]
  related_books: Array<{
    id: number
    title: string
    subtitle?: string | null
    author?: string | null
    cover?: string | null
    rating?: number | null
    recent_reads?: number
    category_name?: string | null
    completion_status?: string
    word_count?: number
  }>
}

export interface ReadingProgress {
  user_id: number
  book_id: number
  section_id: string | null
  paragraph_id: string | null
  scroll_percent: number
  updated_at: string | null
}

export interface ReaderPreferences {
  theme: 'light' | 'dark'
  font_size: number
  show_highlights: boolean
  show_comments: boolean
  updated_at?: string | null
}

export interface ReaderAnalyticsContext {
  session_id?: string
  geo_label?: string
  age_group?: string
}

export interface CreateHighlightPayload {
  paragraph_id: string
  start_offset: number
  end_offset: number
  selected_text: string
  note: string
  color: string
  author?: string
}

export function getReader(bookId: string | number, analytics?: ReaderAnalyticsContext) {
  return request.get<any, ReaderPayload>(`/api/books/${bookId}/reader`, { params: analytics })
}

export function createHighlight(bookId: string | number, payload: CreateHighlightPayload) {
  return request.post<any, { highlight: ReaderHighlight }>(`/api/books/${bookId}/highlights`, payload)
}

export function createHighlightComment(
  bookId: string | number,
  highlightId: number,
  payload: { content: string; author?: string }
) {
  return request.post<any, { comment: ReaderComment }>(
    `/api/books/${bookId}/highlights/${highlightId}/comments`,
    payload
  )
}

export function createBookComment(bookId: string | number, payload: { content: string; author?: string }) {
  return request.post<any, { comment: ReaderComment }>(`/api/books/${bookId}/comments`, payload)
}

export function getBookLanding(bookId: string | number, analytics?: ReaderAnalyticsContext) {
  return request.get<any, BookLandingPayload>(`/api/books/${bookId}/landing`, { params: analytics })
}

export function getReadingProgress(bookId: string | number) {
  return request.get<any, { has_progress: boolean; progress: ReadingProgress | null }>(
    `/api/books/${bookId}/progress`
  )
}

export function saveReadingProgress(
  bookId: string | number,
  payload: {
    section_id: string
    paragraph_id?: string
    scroll_percent: number
    analytics?: ReaderAnalyticsContext & { read_seconds_delta?: number }
  }
) {
  return request.post<any, { progress: ReadingProgress }>(`/api/books/${bookId}/progress`, payload)
}

export function addBookToShelf(bookId: string | number) {
  return request.post<any, { message: string; book_id: number }>('/api/shelf', { book_id: Number(bookId) })
}

export function toggleBookShelf(bookId: string | number, inShelf: boolean) {
  return request.post<any, { message: string; book_id: number; in_shelf: boolean }>('/api/shelf/toggle', {
    book_id: Number(bookId),
    in_shelf: inShelf,
  })
}

export function getReaderPreferences() {
  return request.get<any, ReaderPreferences>('/api/reader/preferences')
}

export function saveReaderPreferences(payload: Partial<ReaderPreferences>) {
  return request.post<any, { message: string; preferences: ReaderPreferences }>('/api/reader/preferences', payload)
}
