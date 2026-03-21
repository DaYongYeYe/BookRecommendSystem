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

export interface CreateHighlightPayload {
  paragraph_id: string
  start_offset: number
  end_offset: number
  selected_text: string
  note: string
  color: string
  author?: string
}

export function getReader(bookId: string | number) {
  return request.get<any, ReaderPayload>(`/api/books/${bookId}/reader`)
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

export function getBookLanding(bookId: string | number) {
  return request.get<any, BookLandingPayload>(`/api/books/${bookId}/landing`)
}

export function getReadingProgress(bookId: string | number) {
  return request.get<any, { has_progress: boolean; progress: ReadingProgress | null }>(
    `/api/books/${bookId}/progress`
  )
}

export function saveReadingProgress(
  bookId: string | number,
  payload: { section_id: string; paragraph_id?: string; scroll_percent: number }
) {
  return request.post<any, { progress: ReadingProgress }>(`/api/books/${bookId}/progress`, payload)
}

export function addBookToShelf(bookId: string | number) {
  return request.post<any, { message: string; book_id: number }>('/api/shelf', { book_id: Number(bookId) })
}

export function getReaderPreferences() {
  return request.get<any, ReaderPreferences>('/api/reader/preferences')
}

export function saveReaderPreferences(payload: Partial<ReaderPreferences>) {
  return request.post<any, { message: string; preferences: ReaderPreferences }>('/api/reader/preferences', payload)
}
