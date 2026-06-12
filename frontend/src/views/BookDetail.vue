<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { useRoute, useRouter } from 'vue-router'
import {
  getBookLanding,
  getReadingProgress,
  toggleBookShelf,
  type BookLandingPayload,
  type ReadingProgress,
} from '@/api/reader'
import { getToken } from '@/api/request'
import { applyBookSeo, applySeo } from '@/utils/seo'

const route = useRoute()
const router = useRouter()
const bookId = computed(() => String(route.params.bookId || '1'))

const loading = ref(false)
const shelfLoading = ref(false)
const landing = ref<BookLandingPayload | null>(null)
const progress = ref<ReadingProgress | null>(null)
const catalogExpanded = ref(false)

const isLoggedIn = computed(() => Boolean(getToken()))
const book = computed(() => landing.value?.book)
const outlinePreview = computed(() => {
  const outline = landing.value?.outline || []
  return catalogExpanded.value ? outline : outline.slice(0, 8)
})
const highlightedComments = computed(() => (landing.value?.book_comments || []).slice(0, 3))
const startButtonText = computed(() => (progress.value?.section_id ? '继续阅读' : '开始阅读'))
const shelfButtonText = computed(() => (book.value?.in_shelf ? '已在书架' : '加入书架'))

const completionStatusText = computed(() => {
  if (book.value?.completion_status === 'completed') return '已完结'
  if (book.value?.completion_status === 'paused') return '暂停更新'
  return '连载中'
})

const progressText = computed(() => {
  if (!progress.value?.section_id) return '还没开始阅读，将从第一章进入正文。'
  return `已保留阅读进度，当前大约读到 ${Math.round(progress.value.scroll_percent || 0)}%。`
})

const relatedSections = computed(() => {
  if (landing.value?.related_sections?.length) {
    return landing.value.related_sections.filter((section) => section.items.length > 0)
  }
  if (landing.value?.related_books?.length) {
    return [
      {
        key: 'related',
        title: '看过本书的人也在读',
        description: '同题材和相近口味的作品。',
        items: landing.value.related_books,
      },
    ]
  }
  return []
})

function formatCount(value?: number | null) {
  const num = Number(value || 0)
  if (num >= 10000) return `${(num / 10000).toFixed(1)}万`
  return String(num)
}

function formatWordCount(value?: number | null) {
  const num = Number(value || 0)
  if (!num) return '未标注'
  if (num >= 10000) return `${(num / 10000).toFixed(1)}万字`
  return `${num}字`
}

function getLandingAnalytics() {
  const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone || ''
  const locale = navigator.language || ''
  return {
    session_id: `l_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`,
    geo_label: timeZone || locale || 'unknown',
    age_group: localStorage.getItem('reader_age_group') || undefined,
  }
}

async function loadData() {
  loading.value = true
  try {
    landing.value = await getBookLanding(bookId.value, getLandingAnalytics())
    applyBookSeo(landing.value.book, `/books/${bookId.value}`)
  } catch (_error) {
    applySeo({
      title: '图书未找到 | 阿书铺子',
      description: '这本书暂时无法访问，返回阿书铺子继续发现其他好书。',
      path: `/books/${bookId.value}`,
      robots: 'noindex,nofollow',
    })
    ElMessage.error('书籍详情加载失败，请稍后重试')
  } finally {
    loading.value = false
  }

  if (getToken()) {
    try {
      const response = await getReadingProgress(bookId.value)
      progress.value = response.has_progress ? response.progress : null
    } catch (_error) {
      progress.value = null
    }
  }
}

function goReader(sectionId?: string) {
  router.push({
    path: `/reader/${bookId.value}`,
    query: {
      ...(!sectionId && progress.value?.section_id ? { resume: '1' } : {}),
      ...(sectionId ? { section: sectionId } : {}),
    },
  })
}

function goListen() {
  router.push({
    path: `/reader/${bookId.value}`,
    query: { ...(progress.value?.section_id ? { resume: '1' } : {}), listen: '1' },
  })
}

async function handleShelfToggle() {
  if (!book.value) return
  if (!isLoggedIn.value) {
    router.push({ path: '/login', query: { redirect: route.fullPath } })
    return
  }

  shelfLoading.value = true
  try {
    const nextValue = !book.value.in_shelf
    await toggleBookShelf(bookId.value, nextValue)
    landing.value = {
      ...landing.value!,
      book: {
        ...landing.value!.book,
        in_shelf: nextValue,
      },
    }
    ElMessage.success(nextValue ? '已加入书架' : '已移出书架')
  } catch (_error) {
    ElMessage.error('书架操作失败，请稍后重试')
  } finally {
    shelfLoading.value = false
  }
}

function goBook(targetBookId: number) {
  router.push(`/books/${targetBookId}`)
}

onMounted(loadData)
watch(bookId, () => {
  progress.value = null
  landing.value = null
  catalogExpanded.value = false
  void loadData()
})
</script>

<template>
  <div class="min-h-screen bg-[linear-gradient(180deg,#f7f1e7_0%,#f5f5f4_30%,#fffaf2_100%)] pb-28 text-[#201813]">
    <div v-if="loading || !landing || !book" class="px-4 py-8">
      <div class="rounded-2xl bg-white p-8 text-center text-sm text-stone-500 shadow-sm">
        正在加载书籍详情...
      </div>
    </div>

    <template v-else>
      <header class="sticky top-0 z-30 border-b border-black/5 bg-[#f7f1e7]/90 px-4 py-3 backdrop-blur md:px-8">
        <div class="mx-auto flex max-w-4xl items-center justify-between">
          <button class="rounded-full px-2 py-1 text-2xl leading-none" @click="router.back()">‹</button>
          <span class="truncate px-4 text-sm font-medium">{{ book.title }}</span>
          <button class="rounded-full px-2 py-1 text-sm text-stone-500" @click="router.push('/')">首页</button>
        </div>
      </header>

      <main class="mx-auto max-w-4xl">
        <section class="px-5 pb-6 pt-5">
          <div class="flex gap-4">
            <img :src="book.cover" :alt="book.title" class="h-40 w-28 shrink-0 rounded-lg object-cover shadow-lg shadow-stone-300" />
            <div class="min-w-0 flex-1 pt-1">
              <h1 class="line-clamp-2 text-2xl font-semibold leading-snug">{{ book.title }}</h1>
              <p v-if="book.subtitle" class="mt-2 line-clamp-2 text-sm leading-6 text-stone-600">{{ book.subtitle }}</p>
              <p class="mt-2 truncate text-sm text-stone-500">{{ book.author || '作者待补充' }}</p>
              <div class="mt-3 flex flex-wrap gap-2">
                <span v-if="book.category" class="rounded-full bg-[#ffe8dc] px-3 py-1 text-xs text-[#e24a1a]">{{ book.category.name }}</span>
                <span class="rounded-full bg-white/70 px-3 py-1 text-xs text-stone-600">{{ completionStatusText }}</span>
                <span v-for="tag in (book.tags || []).slice(0, 2)" :key="tag.id" class="rounded-full bg-white/70 px-3 py-1 text-xs text-stone-600">
                  {{ tag.label }}
                </span>
              </div>
            </div>
          </div>

          <div class="mt-6 grid grid-cols-4 rounded-2xl bg-white/75 py-4 text-center shadow-sm">
            <div>
              <p class="text-lg font-semibold">{{ book.rating || '-' }}</p>
              <p class="mt-1 text-xs text-stone-500">评分</p>
            </div>
            <div>
              <p class="text-lg font-semibold">{{ formatCount(book.rating_count) }}</p>
              <p class="mt-1 text-xs text-stone-500">评分人数</p>
            </div>
            <div>
              <p class="text-lg font-semibold">{{ formatWordCount(book.word_count) }}</p>
              <p class="mt-1 text-xs text-stone-500">字数</p>
            </div>
            <div>
              <p class="text-lg font-semibold">{{ formatCount(book.recent_reads) }}</p>
              <p class="mt-1 text-xs text-stone-500">在读</p>
            </div>
          </div>

          <p class="mt-3 text-xs text-stone-500">{{ progressText }}</p>
        </section>

        <section v-if="book.decision_points?.length" class="mx-4 rounded-2xl bg-white p-4 shadow-sm">
          <h2 class="text-base font-semibold">推荐看点</h2>
          <div class="mt-3 flex gap-2 overflow-x-auto pb-1">
            <span v-for="point in book.decision_points" :key="point" class="shrink-0 rounded-full bg-[#fff2ea] px-3 py-2 text-sm text-[#d94d1f]">
              {{ point }}
            </span>
          </div>
        </section>

        <section class="mx-4 mt-4 rounded-2xl bg-white p-4 shadow-sm">
          <div class="flex items-center justify-between">
            <h2 class="text-base font-semibold">简介</h2>
            <span class="text-xs text-stone-400">{{ book.estimated_reading_minutes ? `${book.estimated_reading_minutes} 分钟` : '沉浸阅读' }}</span>
          </div>
          <p class="mt-3 text-sm leading-7 text-stone-700">{{ book.description }}</p>
          <p v-if="book.recommendation_reason" class="mt-3 rounded-2xl bg-[#fff7ed] px-3 py-3 text-sm leading-6 text-[#9a4a24]">
            {{ book.recommendation_reason }}
          </p>
        </section>

        <section class="mx-4 mt-4 rounded-2xl bg-white p-4 shadow-sm">
          <div class="flex items-center justify-between">
            <div>
              <h2 class="text-base font-semibold">目录</h2>
              <p class="mt-1 text-xs text-stone-500">{{ landing.outline.length }} 章 · {{ completionStatusText }}</p>
            </div>
            <button class="text-sm text-[#ff5a2a]" @click="catalogExpanded = !catalogExpanded">
              {{ catalogExpanded ? '收起' : '全部目录' }}
            </button>
          </div>

          <div class="mt-3 divide-y divide-stone-100">
            <button
              v-for="(item, index) in outlinePreview"
              :key="item.id"
              class="flex w-full items-center gap-3 py-4 text-left"
              @click="goReader(item.id)"
            >
              <span class="w-7 text-xs text-stone-400">{{ index + 1 }}</span>
              <span class="min-w-0 flex-1 truncate text-sm" :class="item.level === 2 ? 'pl-4 text-stone-500' : 'text-stone-800'">
                {{ item.title }}
              </span>
              <span v-if="progress?.section_id === item.id" class="rounded-full bg-[#fff1e8] px-2 py-1 text-xs text-[#ff5a2a]">上次读到</span>
            </button>
          </div>
        </section>

        <section class="mx-4 mt-4 rounded-2xl bg-white p-4 shadow-sm">
          <div class="flex items-center justify-between">
            <h2 class="text-base font-semibold">读者评论</h2>
            <span class="text-xs text-stone-400">{{ landing.book_comments.length }} 条</span>
          </div>
          <div class="mt-3 space-y-3">
            <div v-for="comment in highlightedComments" :key="comment.id" class="rounded-2xl bg-stone-50 px-3 py-3">
              <div class="flex items-center justify-between text-xs text-stone-400">
                <span>{{ comment.author }}</span>
                <span>{{ comment.created_at }}</span>
              </div>
              <p class="mt-2 line-clamp-3 text-sm leading-6 text-stone-700">{{ comment.content }}</p>
            </div>
            <div v-if="landing.book_comments.length === 0" class="rounded-2xl bg-stone-50 px-3 py-6 text-center text-sm text-stone-500">
              还没有评论，开始阅读后可以留下书评或段评。
            </div>
          </div>
        </section>

        <section v-for="section in relatedSections" :key="section.key" class="mx-4 mt-4 rounded-2xl bg-white p-4 shadow-sm">
          <div class="flex items-end justify-between gap-3">
            <div>
              <h2 class="text-base font-semibold">{{ section.title }}</h2>
              <p class="mt-1 text-xs text-stone-500">{{ section.description }}</p>
            </div>
          </div>
          <div class="mt-4 flex gap-3 overflow-x-auto pb-2">
            <button v-for="item in section.items" :key="`${section.key}-${item.id}`" class="w-28 shrink-0 text-left" @click="goBook(item.id)">
              <img :src="item.cover || ''" :alt="item.title" class="h-36 w-24 rounded-md object-cover shadow" />
              <span class="mt-2 block line-clamp-2 text-sm font-medium">{{ item.title }}</span>
              <span class="mt-1 block truncate text-xs text-stone-500">{{ item.author || '作者待补充' }}</span>
              <span class="mt-1 block text-xs text-stone-400">{{ item.rating || '-' }} 分 · {{ formatWordCount(item.word_count) }}</span>
            </button>
          </div>
        </section>
      </main>

      <footer class="fixed inset-x-0 bottom-0 z-40 border-t border-black/5 bg-white/95 px-4 pb-[max(0.75rem,env(safe-area-inset-bottom))] pt-3 backdrop-blur">
        <div class="mx-auto grid max-w-4xl grid-cols-[1fr_1.4fr_1fr] gap-3">
          <button
            class="rounded-full border border-stone-200 bg-white px-3 py-3 text-sm font-medium text-stone-700 disabled:opacity-60"
            :disabled="shelfLoading"
            @click="handleShelfToggle"
          >
            {{ shelfLoading ? '处理中...' : shelfButtonText }}
          </button>
          <button class="rounded-full bg-[#ff5a2a] px-3 py-3 text-sm font-semibold text-white shadow-lg shadow-orange-200" @click="goReader()">
            {{ startButtonText }}
          </button>
          <button class="rounded-full border border-stone-200 bg-white px-3 py-3 text-sm font-medium text-stone-700" @click="goListen">
            听书
          </button>
        </div>
      </footer>
    </template>
  </div>
</template>
