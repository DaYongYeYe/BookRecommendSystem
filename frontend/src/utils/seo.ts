import type { RouteLocationNormalizedLoaded } from 'vue-router'
import type { ReaderBook } from '@/api/reader'

export const SITE_NAME = '阿书铺子'
export const DEFAULT_TITLE = `${SITE_NAME} | 现代图书推荐系统`
export const DEFAULT_DESCRIPTION = '阿书铺子是一个现代图书推荐系统，提供热门榜单、分类发现、个性化推荐和沉浸式阅读体验。'

export interface SeoMeta {
  title?: string
  description?: string
  path?: string
  image?: string | null
  type?: 'website' | 'book'
  robots?: string
}

export function publicSiteUrl() {
  const configured = (import.meta.env.VITE_SITE_PUBLIC_URL || '').replace(/\/+$/, '')
  if (configured) return configured
  return window.location.origin
}

export function absoluteUrl(pathOrUrl?: string | null) {
  const value = (pathOrUrl || '').trim()
  if (!value) return ''
  if (/^https?:\/\//i.test(value)) return value
  return new URL(value.startsWith('/') ? value : `/${value}`, `${publicSiteUrl()}/`).toString()
}

function upsertMeta(selector: string, attrs: Record<string, string>) {
  let element = document.head.querySelector<HTMLMetaElement>(selector)
  if (!element) {
    element = document.createElement('meta')
    const name = attrs.name || attrs.property
    if (attrs.name) element.setAttribute('name', name)
    if (attrs.property) element.setAttribute('property', name)
    document.head.appendChild(element)
  }
  Object.entries(attrs).forEach(([key, value]) => element?.setAttribute(key, value))
}

function upsertCanonical(href: string) {
  let element = document.head.querySelector<HTMLLinkElement>('link[rel="canonical"]')
  if (!element) {
    element = document.createElement('link')
    element.setAttribute('rel', 'canonical')
    document.head.appendChild(element)
  }
  element.setAttribute('href', href)
}

export function applySeo(meta: SeoMeta = {}) {
  const title = meta.title || DEFAULT_TITLE
  const description = meta.description || DEFAULT_DESCRIPTION
  const canonical = absoluteUrl(meta.path || window.location.pathname)
  const robots = meta.robots || 'index,follow'
  const type = meta.type || 'website'
  const image = absoluteUrl(meta.image)

  document.title = title
  upsertCanonical(canonical)
  upsertMeta('meta[name="description"]', { name: 'description', content: description })
  upsertMeta('meta[name="robots"]', { name: 'robots', content: robots })
  upsertMeta('meta[property="og:site_name"]', { property: 'og:site_name', content: SITE_NAME })
  upsertMeta('meta[property="og:type"]', { property: 'og:type', content: type })
  upsertMeta('meta[property="og:title"]', { property: 'og:title', content: title })
  upsertMeta('meta[property="og:description"]', { property: 'og:description', content: description })
  upsertMeta('meta[property="og:url"]', { property: 'og:url', content: canonical })
  upsertMeta('meta[name="twitter:card"]', { name: 'twitter:card', content: image ? 'summary_large_image' : 'summary' })
  upsertMeta('meta[name="twitter:title"]', { name: 'twitter:title', content: title })
  upsertMeta('meta[name="twitter:description"]', { name: 'twitter:description', content: description })

  const ogImage = document.head.querySelector<HTMLMetaElement>('meta[property="og:image"]')
  const twitterImage = document.head.querySelector<HTMLMetaElement>('meta[name="twitter:image"]')
  if (image) {
    upsertMeta('meta[property="og:image"]', { property: 'og:image', content: image })
    upsertMeta('meta[name="twitter:image"]', { name: 'twitter:image', content: image })
  } else {
    ogImage?.remove()
    twitterImage?.remove()
  }
}

export function applyRouteSeo(route: RouteLocationNormalizedLoaded) {
  const meta = route.meta.seo as SeoMeta | undefined
  const robots = route.meta.requiresAuth || route.meta.requiresAdmin || route.meta.requiresCreator ? 'noindex,nofollow' : meta?.robots
  applySeo({
    ...meta,
    path: meta?.path || route.path,
    robots,
  })
}

export function applyBookSeo(book: ReaderBook, path: string) {
  const author = book.author ? ` - ${book.author}` : ''
  const category = book.category?.name ? `，${book.category.name}` : ''
  const description =
    compactText(book.description, 150) || `在${SITE_NAME}查看《${book.title}》的简介、评分${category}和相关推荐。`
  applySeo({
    title: `${book.title}${author} | ${SITE_NAME}`,
    description,
    path,
    image: book.cover,
    type: 'book',
  })
}

function compactText(value: string | undefined, maxLength: number) {
  const text = (value || '').replace(/\s+/g, ' ').trim()
  if (text.length <= maxLength) return text
  return `${text.slice(0, maxLength - 1).trim()}…`
}
