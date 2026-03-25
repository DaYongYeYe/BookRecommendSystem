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
    ElMessage.error('图书介绍加载失败')
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
        正在加载图书介绍...
      </div>

      <template v-else>
        <section class="overflow-hidden rounded-[2rem] bg-white shadow-lg shadow-stone-200/60">
          <div class="grid gap-8 p-6 md:grid-cols-[280px_minmax(0,1fr)] md:p-10">
            <img :src="landing.book.cover" :alt="landing.book.title" class="h-[380px] w-full rounded-3xl object-cover shadow-md" />
            <div>
              <p class="text-xs uppercase tracking-[0.38em] text-stone-400">Book Intro</p>
              <h1 class="mt-3 text-4xl font-semibold leading-tight text-stone-900">{{ landing.book.title }}</h1>
              <p class="mt-3 text-lg text-stone-600">{{ landing.book.subtitle }}</p>
              <p class="mt-2 text-sm text-stone-500">作者：{{ landing.book.author }}</p>

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
                  @click="goReader"
                >
                  下一页：进入正文
                </button>
                <span v-if="progress?.section_id" class="text-xs text-stone-500">
                  已有阅读进度，将跳转到上次位置
                </span>
              </div>
            </div>
          </div>
        </section>

        <section class="mt-8 rounded-[2rem] bg-[#122620] p-6 text-stone-100 shadow-lg shadow-stone-200/40 md:p-8">
          <div class="flex items-center justify-between">
            <h2 class="text-2xl font-semibold">书本评论</h2>
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
          </div>
        </section>
      </template>
    </div>
  </div>
</template>
