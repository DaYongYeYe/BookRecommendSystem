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

const route = useRoute()
const router = useRouter()
const bookId = computed(() => String(route.params.bookId || '1'))

const loading = ref(false)
const shelfLoading = ref(false)
const landing = ref<BookLandingPayload | null>(null)
const progress = ref<ReadingProgress | null>(null)

const isLoggedIn = computed(() => Boolean(getToken()))
const book = computed(() => landing.value?.book)

const startButtonText = computed(() => (progress.value?.section_id ? '继续阅读' : '开始阅读'))
const shelfButtonText = computed(() => (book.value?.in_shelf ? '已在书架' : '加入书架'))
const completionStatusText = computed(() => {
  if (book.value?.completion_status === 'completed') return '已完结'
  if (book.value?.completion_status === 'paused') return '暂停更新'
  return '连载中'
})
const progressText = computed(() => {
  if (!progress.value?.section_id) {
    return '还没开始的话，会从第一章进入正文。'
  }
  return `已为你保留阅读进度，当前大约读到 ${Math.round(progress.value.scroll_percent || 0)}%。`
})

function formatCount(value?: number) {
  const num = Number(value || 0)
  if (num >= 10000) {
    return `${(num / 10000).toFixed(1)} 万`
  }
  return String(num)
}

function formatWordCount(value?: number) {
  const num = Number(value || 0)
  if (!num) return '未标注'
  if (num >= 10000) {
    return `${(num / 10000).toFixed(1)} 万字`
  }
  return `${num} 字`
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
  } catch (_error) {
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

function goReader() {
  router.push({
    path: `/reader/${bookId.value}`,
    query: progress.value?.section_id ? { resume: '1' } : {},
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
  loadData()
})
</script>

<template>
  <div class="min-h-screen bg-[linear-gradient(180deg,#f7f1e7_0%,#f5f5f4_30%,#fffaf2_100%)] px-4 py-10 text-stone-900">
    <div class="mx-auto max-w-6xl">
      <div v-if="loading || !landing || !book" class="rounded-3xl bg-white p-12 text-center text-stone-500 shadow-sm">
        正在加载书籍详情...
      </div>

      <template v-else>
        <section class="overflow-hidden rounded-[2rem] bg-white shadow-lg shadow-stone-200/70">
          <div class="grid gap-8 p-6 md:grid-cols-[280px_minmax(0,1fr)] md:p-10">
            <div>
              <img :src="book.cover" :alt="book.title" class="h-[380px] w-full rounded-3xl object-cover shadow-md" />
              <div class="mt-5 rounded-3xl bg-stone-900 p-5 text-stone-50">
                <p class="text-xs uppercase tracking-[0.34em] text-stone-300">Quick Decision</p>
                <ul class="mt-4 space-y-3 text-sm leading-6 text-stone-100">
                  <li v-for="point in book.decision_points || []" :key="point" class="rounded-2xl bg-white/10 px-4 py-3">
                    {{ point }}
                  </li>
                </ul>
              </div>
            </div>

            <div>
              <p class="text-xs uppercase tracking-[0.38em] text-stone-400">Book Detail</p>
              <h1 class="mt-3 text-4xl font-semibold leading-tight text-stone-900">{{ book.title }}</h1>
              <p v-if="book.subtitle" class="mt-3 text-lg text-stone-600">{{ book.subtitle }}</p>
              <p class="mt-2 text-sm text-stone-500">作者：{{ book.author || '作者待补充' }}</p>

              <div class="mt-4 flex flex-wrap items-center gap-2">
                <span v-if="book.category" class="rounded-full bg-orange-100 px-4 py-2 text-xs font-medium text-orange-700">
                  {{ book.category.name }}
                </span>
                <span
                  v-for="tag in book.tags || []"
                  :key="tag.id"
                  class="rounded-full bg-stone-100 px-4 py-2 text-xs font-medium text-stone-600"
                >
                  {{ tag.label }}
                </span>
              </div>

              <div class="mt-6 grid gap-3 sm:grid-cols-3">
                <div class="rounded-2xl bg-stone-50 p-4">
                  <p class="text-xs text-stone-400">读者评分</p>
                  <p class="mt-2 text-2xl font-semibold text-stone-900">{{ book.rating || '-' }}</p>
                </div>
                <div class="rounded-2xl bg-stone-50 p-4">
                  <p class="text-xs text-stone-400">评分人数</p>
                  <p class="mt-2 text-2xl font-semibold text-stone-900">{{ formatCount(book.rating_count) }}</p>
                </div>
                <div class="rounded-2xl bg-stone-50 p-4">
                  <p class="text-xs text-stone-400">最近在读</p>
                  <p class="mt-2 text-2xl font-semibold text-stone-900">{{ formatCount(book.recent_reads) }}</p>
                </div>
              </div>

              <div class="mt-6 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                <div class="rounded-3xl border border-stone-200 px-4 py-4">
                  <p class="text-xs text-stone-400">字数</p>
                  <p class="mt-2 text-base font-semibold text-stone-900">{{ formatWordCount(book.word_count) }}</p>
                </div>
                <div class="rounded-3xl border border-stone-200 px-4 py-4">
                  <p class="text-xs text-stone-400">连载状态</p>
                  <p class="mt-2 text-base font-semibold text-stone-900">{{ completionStatusText }}</p>
                </div>
                <div class="rounded-3xl border border-stone-200 px-4 py-4">
                  <p class="text-xs text-stone-400">预计阅读</p>
                  <p class="mt-2 text-base font-semibold text-stone-900">
                    {{ book.estimated_reading_minutes ? `${book.estimated_reading_minutes} 分钟` : '未标注' }}
                  </p>
                </div>
                <div class="rounded-3xl border border-stone-200 px-4 py-4">
                  <p class="text-xs text-stone-400">适合谁读</p>
                  <p class="mt-2 text-sm font-medium leading-6 text-stone-800">
                    {{ book.suitable_audience || '适合想先看清题材和节奏，再决定是否开读的读者。' }}
                  </p>
                </div>
              </div>

              <div class="mt-6 rounded-3xl bg-stone-50 p-6">
                <p class="text-xs uppercase tracking-[0.3em] text-stone-400">Recommendation</p>
                <p class="mt-3 text-sm leading-7 text-stone-700">
                  {{ book.recommendation_reason || '如果你正在找一本题材明确、口碑稳定、节奏可预期的书，这本值得先点开看看。' }}
                </p>
              </div>

              <div class="mt-6 rounded-3xl bg-stone-50 p-6">
                <p class="text-sm leading-8 text-stone-700">{{ book.description }}</p>
              </div>

              <div class="mt-6 flex flex-wrap items-center gap-3">
                <button
                  class="rounded-full bg-stone-900 px-7 py-3 text-sm font-medium text-white transition hover:bg-stone-700"
                  @click="goReader"
                >
                  {{ startButtonText }}
                </button>
                <button
                  class="rounded-full border border-stone-300 bg-white px-7 py-3 text-sm font-medium text-stone-700 transition hover:border-stone-500"
                  :disabled="shelfLoading"
                  @click="handleShelfToggle"
                >
                  {{ shelfLoading ? '处理中...' : shelfButtonText }}
                </button>
                <button
                  class="rounded-full border border-stone-300 bg-white px-7 py-3 text-sm font-medium text-stone-700 transition hover:border-stone-500"
                  @click="router.push('/')"
                >
                  返回首页
                </button>
              </div>

              <p class="mt-3 text-xs text-stone-500">{{ progressText }}</p>
            </div>
          </div>
        </section>

        <section class="mt-8 grid gap-6 xl:grid-cols-[minmax(0,1fr)_340px]">
          <div class="space-y-6">
            <section class="rounded-[2rem] bg-white p-6 shadow-sm md:p-8">
              <div class="flex items-center justify-between">
                <div>
                  <h2 class="text-2xl font-semibold">目录预览</h2>
                  <p class="mt-1 text-sm text-stone-500">先看结构和章节感受，再决定要不要立刻开读。</p>
                </div>
                <span class="text-sm text-stone-400">{{ landing.outline.length }} 章</span>
              </div>
              <div class="mt-5 space-y-3">
                <div
                  v-for="item in landing.outline"
                  :key="item.id"
                  class="rounded-2xl border border-stone-100 px-4 py-4"
                  :class="item.level === 2 ? 'ml-4' : ''"
                >
                  <p class="text-sm font-medium text-stone-800">{{ item.title }}</p>
                </div>
              </div>
            </section>

            <section class="rounded-[2rem] bg-[#122620] p-6 text-stone-100 shadow-lg shadow-stone-200/40 md:p-8">
              <div class="flex items-center justify-between">
                <div>
                  <h2 class="text-2xl font-semibold">读者评论</h2>
                  <p class="mt-1 text-sm text-stone-300">看看别人为什么开始，也看看他们为什么停留。</p>
                </div>
                <span class="rounded-full bg-white/10 px-3 py-2 text-xs">
                  {{ landing.book_comments.length }} 条
                </span>
              </div>

              <div class="mt-6 space-y-3">
                <div
                  v-for="comment in landing.book_comments"
                  :key="comment.id"
                  class="rounded-3xl bg-white/10 px-4 py-4"
                >
                  <div class="flex items-center justify-between text-xs text-stone-300">
                    <span>{{ comment.author }}</span>
                    <span>{{ comment.created_at }}</span>
                  </div>
                  <p class="mt-2 text-sm leading-7 text-stone-100">{{ comment.content }}</p>
                </div>
                <div v-if="landing.book_comments.length === 0" class="rounded-3xl bg-white/5 px-4 py-6 text-sm text-stone-300">
                  还没有评论，欢迎成为第一个留下读后感的人。
                </div>
              </div>
            </section>
          </div>

          <section class="rounded-[2rem] bg-white p-6 shadow-sm md:p-8">
            <div>
              <h2 class="text-2xl font-semibold">相关推荐</h2>
              <p class="mt-1 text-sm text-stone-500">如果这本的题材和阅读负担对味，这几本也值得顺手放进候选。</p>
            </div>

            <div class="mt-6 space-y-4">
              <button
                v-for="item in landing.related_books"
                :key="item.id"
                class="flex w-full items-start gap-4 rounded-3xl border border-stone-200 p-3 text-left transition hover:border-stone-400 hover:bg-stone-50"
                @click="goBook(item.id)"
              >
                <img :src="item.cover" :alt="item.title" class="h-24 w-16 rounded-2xl object-cover" />
                <div class="min-w-0 flex-1">
                  <p class="truncate text-sm font-semibold text-stone-900">{{ item.title }}</p>
                  <p class="mt-1 text-xs text-stone-500">{{ item.author || '作者待补充' }}</p>
                  <p class="mt-2 text-xs text-stone-500">
                    {{ item.category_name || '同类推荐' }} · {{ formatWordCount(item.word_count) }}
                  </p>
                  <p class="mt-2 text-xs text-stone-600">
                    评分 {{ item.rating || '-' }} · {{ formatCount(item.recent_reads) }} 人在读
                  </p>
                </div>
              </button>

              <div v-if="landing.related_books.length === 0" class="rounded-3xl bg-stone-50 px-4 py-6 text-sm text-stone-500">
                暂时还没有相关推荐。
              </div>
            </div>
          </section>
        </section>
      </template>
    </div>
  </div>
</template>
