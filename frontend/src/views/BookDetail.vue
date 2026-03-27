<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { useRoute, useRouter } from 'vue-router'
import { getBookLanding, getReadingProgress, type BookLandingPayload, type ReadingProgress } from '@/api/reader'
import { getToken } from '@/api/request'

const route = useRoute()
const router = useRouter()
const bookId = computed(() => String(route.params.bookId || '1'))

const loading = ref(false)
const landing = ref<BookLandingPayload | null>(null)
const progress = ref<ReadingProgress | null>(null)

const startButtonText = computed(() => (progress.value?.section_id ? '继续阅读' : '开始阅读'))
const progressText = computed(() => {
  if (!progress.value?.section_id) {
    return '首次阅读将从开篇进入正文。'
  }
  return `已为你保留阅读进度，当前约读到 ${Math.round(progress.value.scroll_percent || 0)}%。`
})

function formatCount(value?: number) {
  const num = Number(value || 0)
  if (num >= 10000) {
    return `${(num / 10000).toFixed(1)} 万`
  }
  return String(num)
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

onMounted(loadData)
</script>

<template>
  <div class="min-h-screen bg-gradient-to-b from-stone-100 via-stone-100 to-orange-50/60 px-4 py-10 text-stone-900">
    <div class="mx-auto max-w-6xl">
      <div v-if="loading || !landing" class="rounded-3xl bg-white p-12 text-center text-stone-500 shadow-sm">
        正在加载书籍详情...
      </div>

      <template v-else>
        <section class="overflow-hidden rounded-[2rem] bg-white shadow-lg shadow-stone-200/60">
          <div class="grid gap-8 p-6 md:grid-cols-[280px_minmax(0,1fr)] md:p-10">
            <img :src="landing.book.cover" :alt="landing.book.title" class="h-[380px] w-full rounded-3xl object-cover shadow-md" />
            <div>
              <p class="text-xs uppercase tracking-[0.38em] text-stone-400">Book Detail</p>
              <h1 class="mt-3 text-4xl font-semibold leading-tight text-stone-900">{{ landing.book.title }}</h1>
              <p v-if="landing.book.subtitle" class="mt-3 text-lg text-stone-600">{{ landing.book.subtitle }}</p>
              <p class="mt-2 text-sm text-stone-500">作者：{{ landing.book.author || '作者待补充' }}</p>

              <div class="mt-6 grid gap-3 sm:grid-cols-3">
                <div class="rounded-2xl bg-stone-50 p-4">
                  <p class="text-xs text-stone-400">读者评分</p>
                  <p class="mt-2 text-2xl font-semibold text-stone-900">{{ landing.book.rating || '-' }}</p>
                </div>
                <div class="rounded-2xl bg-stone-50 p-4">
                  <p class="text-xs text-stone-400">评分人数</p>
                  <p class="mt-2 text-2xl font-semibold text-stone-900">{{ formatCount(landing.book.rating_count) }}</p>
                </div>
                <div class="rounded-2xl bg-stone-50 p-4">
                  <p class="text-xs text-stone-400">最近在读</p>
                  <p class="mt-2 text-2xl font-semibold text-stone-900">{{ formatCount(landing.book.recent_reads) }}</p>
                </div>
              </div>

              <div class="mt-6 rounded-3xl bg-stone-50 p-6">
                <p class="text-sm leading-8 text-stone-700">{{ landing.book.description }}</p>
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
                  @click="router.push('/')"
                >
                  返回首页
                </button>
                <span class="text-xs text-stone-500">
                  {{ progressText }}
                </span>
              </div>
            </div>
          </div>
        </section>

        <section class="mt-8 grid gap-6 lg:grid-cols-[minmax(0,1fr)_360px]">
          <div class="rounded-[2rem] bg-white p-6 shadow-sm md:p-8">
            <div class="flex items-center justify-between">
              <h2 class="text-2xl font-semibold">目录预览</h2>
              <span class="text-sm text-stone-400">{{ landing.outline.length }} 节</span>
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
          </div>

          <section class="rounded-[2rem] bg-[#122620] p-6 text-stone-100 shadow-lg shadow-stone-200/40 md:p-8">
            <div class="flex items-center justify-between">
              <h2 class="text-2xl font-semibold">读者评论</h2>
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
        </section>
      </template>
    </div>
  </div>
</template>
