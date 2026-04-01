<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import type { HomeBookItem } from '@/api/home'
import { getToken } from '@/api/request'
import {
  clearSearchHistory,
  getHotSearchTerms,
  getSearchHistory,
  searchBooks,
  type SearchHistoryItem,
  type SearchHotTermItem,
} from '@/api/search'

const LOCAL_HISTORY_KEY = 'book_search_history'

const route = useRoute()
const router = useRouter()

const keyword = ref('')
const loading = ref(false)
const searched = ref(false)
const currentQuery = ref('')
const results = ref<HomeBookItem[]>([])
const recommendations = ref<HomeBookItem[]>([])
const hotTerms = ref<SearchHotTermItem[]>([])
const historyItems = ref<SearchHistoryItem[]>([])

const isLoggedIn = computed(() => Boolean(getToken()))
const showEmptyState = computed(
  () => searched.value && !loading.value && Boolean(currentQuery.value) && results.value.length === 0
)

function goBook(bookId: number) {
  router.push(`/books/${bookId}`)
}

function readLocalHistory(): SearchHistoryItem[] {
  try {
    const raw = localStorage.getItem(LOCAL_HISTORY_KEY)
    const parsed = raw ? JSON.parse(raw) : []
    if (!Array.isArray(parsed)) return []
    return parsed
      .filter((item) => typeof item?.keyword === 'string' && item.keyword.trim())
      .map((item) => ({
        keyword: item.keyword.trim(),
      }))
      .slice(0, 8)
  } catch {
    return []
  }
}

function writeLocalHistory(items: SearchHistoryItem[]) {
  localStorage.setItem(LOCAL_HISTORY_KEY, JSON.stringify(items.slice(0, 8)))
}

function addLocalHistory(keywordValue: string) {
  const normalized = keywordValue.trim()
  if (!normalized) return
  const nextItems = readLocalHistory().filter((item) => item.keyword !== normalized)
  nextItems.unshift({ keyword: normalized })
  writeLocalHistory(nextItems)
}

function clearLocalHistory() {
  localStorage.removeItem(LOCAL_HISTORY_KEY)
}

async function loadHotTerms() {
  try {
    const res = await getHotSearchTerms(8)
    hotTerms.value = res.items || []
  } catch {
    hotTerms.value = []
  }
}

async function loadHistory() {
  if (isLoggedIn.value) {
    try {
      const res = await getSearchHistory(8)
      historyItems.value = res.items || []
      return
    } catch {
      historyItems.value = []
      return
    }
  }
  historyItems.value = readLocalHistory()
}

async function runSearch(rawKeyword = keyword.value, syncRoute = true) {
  const q = rawKeyword.trim()
  keyword.value = q

  if (syncRoute) {
    await router.replace({
      path: '/search',
      query: q ? { q } : {},
    })
  }

  if (!q) {
    searched.value = false
    currentQuery.value = ''
    results.value = []
    recommendations.value = []
    return
  }

  loading.value = true
  try {
    const res = await searchBooks({ q, limit: 18, recommend_limit: 4 })
    currentQuery.value = res.query || q
    results.value = res.items || []
    recommendations.value = res.recommended_items || []
    searched.value = true

    if (!isLoggedIn.value) {
      addLocalHistory(q)
    }
    await loadHistory()
  } catch (_error) {
    searched.value = true
    currentQuery.value = q
    results.value = []
    recommendations.value = []
    ElMessage.warning('搜索失败，请稍后重试')
  } finally {
    loading.value = false
  }
}

async function handleSearch() {
  await runSearch(keyword.value, true)
}

async function useKeyword(value: string) {
  keyword.value = value
  await runSearch(value, true)
}

async function handleClearHistory() {
  try {
    if (isLoggedIn.value) {
      await clearSearchHistory()
    } else {
      clearLocalHistory()
    }
    historyItems.value = []
    ElMessage.success('已清空搜索记录')
  } catch {
    ElMessage.warning('清空失败，请稍后再试')
  }
}

watch(
  () => route.query.q,
  async (value) => {
    const nextQuery = typeof value === 'string' ? value.trim() : ''
    keyword.value = nextQuery

    if (!nextQuery) {
      searched.value = false
      currentQuery.value = ''
      results.value = []
      recommendations.value = []
      return
    }

    if (nextQuery === currentQuery.value && searched.value) {
      return
    }

    await runSearch(nextQuery, false)
  },
  { immediate: true }
)

onMounted(async () => {
  await Promise.allSettled([loadHotTerms(), loadHistory()])
})
</script>

<template>
  <div class="min-h-screen bg-[linear-gradient(180deg,#f6f3ee_0%,#f2efe8_26%,#fbfaf7_100%)] text-stone-900">
    <header class="sticky top-0 z-30 border-b border-stone-200 bg-white/92 backdrop-blur">
      <div class="mx-auto flex max-w-6xl items-center gap-3 px-4 py-3">
        <button
          class="rounded-full border border-stone-300 px-4 py-2 text-sm text-stone-700 transition hover:border-stone-500"
          @click="router.push('/')"
        >
          返回首页
        </button>

        <form
          class="flex min-w-0 flex-1 items-center gap-3 rounded-full border border-stone-200 bg-stone-50 px-4 py-2 shadow-sm"
          @submit.prevent="handleSearch"
        >
          <input
            v-model="keyword"
            type="text"
            class="w-full bg-transparent text-sm text-stone-900 outline-none placeholder:text-stone-400"
            placeholder="搜索书名/作者/关键词"
          />
          <button class="rounded-full bg-stone-900 px-5 py-2 text-sm font-medium text-white" :disabled="loading">
            {{ loading ? '搜索中...' : '搜索' }}
          </button>
        </form>
      </div>
    </header>

    <main class="mx-auto max-w-6xl px-4 py-8">
      <section class="overflow-hidden rounded-[2rem] bg-[#1e1e1e] p-6 text-white shadow-lg shadow-stone-300/30 md:p-8">
        <div class="grid gap-6 lg:grid-cols-[minmax(0,1fr)_320px]">
          <div>
            <p class="text-sm uppercase tracking-[0.32em] text-stone-400">Search Books</p>
            <h1 class="mt-3 text-3xl font-semibold leading-tight md:text-4xl">
              直接搜书名、作者、标签和剧情关键词。
            </h1>
            <p class="mt-3 max-w-2xl text-sm leading-7 text-stone-300">
              输入后点“搜索”即可查找小说；也可以直接点热门词或历史记录，快速重走上一次找书路径。
            </p>
          </div>

          <div class="rounded-[1.6rem] bg-white/8 p-5 backdrop-blur">
            <p class="text-xs uppercase tracking-[0.28em] text-stone-400">Search Guide</p>
            <ul class="mt-4 space-y-3 text-sm leading-6 text-stone-200">
              <li class="rounded-2xl bg-white/8 px-4 py-3">支持检索：书名、作者名、标签/题材、简介关键词</li>
              <li class="rounded-2xl bg-white/8 px-4 py-3">无结果时会提供推荐内容，避免搜索落空</li>
              <li class="rounded-2xl bg-white/8 px-4 py-3">登录后会保留最近搜索；未登录会保存在本地浏览器</li>
            </ul>
          </div>
        </div>
      </section>

      <section class="mt-8 grid gap-5 lg:grid-cols-[minmax(0,1fr)_320px]">
        <div class="rounded-[2rem] bg-white p-6 shadow-sm">
          <div class="flex items-center justify-between gap-4">
            <div>
              <h2 class="text-xl font-semibold">热门搜索</h2>
              <p class="mt-1 text-sm text-stone-500">点击短标签可直接发起搜索。</p>
            </div>
          </div>

          <div class="mt-4 flex flex-wrap gap-3">
            <button
              v-for="item in hotTerms"
              :key="item.keyword"
              class="rounded-full border border-stone-200 bg-stone-50 px-4 py-2 text-sm text-stone-700 transition hover:border-stone-400 hover:bg-white"
              @click="useKeyword(item.keyword)"
            >
              {{ item.keyword }}
            </button>
            <p v-if="hotTerms.length === 0" class="text-sm text-stone-400">热门搜索正在准备中</p>
          </div>
        </div>

        <aside class="rounded-[2rem] bg-white p-6 shadow-sm">
          <div class="flex items-center justify-between gap-4">
            <div>
              <h2 class="text-xl font-semibold">最近搜索</h2>
              <p class="mt-1 text-sm text-stone-500">点一下即可再次搜索。</p>
            </div>
            <button
              v-if="historyItems.length"
              class="text-sm text-stone-500 transition hover:text-stone-900"
              @click="handleClearHistory"
            >
              清空
            </button>
          </div>

          <div class="mt-4 flex flex-wrap gap-3">
            <button
              v-for="item in historyItems"
              :key="item.id || item.keyword"
              class="rounded-full border border-stone-200 px-4 py-2 text-sm text-stone-700 transition hover:border-stone-400 hover:bg-stone-50"
              @click="useKeyword(item.keyword)"
            >
              {{ item.keyword }}
            </button>
            <p v-if="historyItems.length === 0" class="text-sm text-stone-400">还没有搜索记录，先搜一本试试。</p>
          </div>
        </aside>
      </section>

      <section v-if="loading" class="mt-8 rounded-[2rem] bg-white p-8 text-center text-sm text-stone-500 shadow-sm">
        搜索中，请稍候...
      </section>

      <section v-else-if="results.length > 0" class="mt-8">
        <div class="mb-4 flex items-end justify-between gap-4">
          <div>
            <h2 class="text-2xl font-semibold">搜索结果</h2>
            <p class="mt-1 text-sm text-stone-500">“{{ currentQuery }}” 共找到 {{ results.length }} 本相关书籍。</p>
          </div>
        </div>

        <div class="grid gap-5 sm:grid-cols-2 xl:grid-cols-3">
          <article
            v-for="book in results"
            :key="book.id"
            class="cursor-pointer rounded-[1.6rem] bg-white p-4 shadow-sm transition hover:-translate-y-0.5 hover:shadow-md"
            @click="goBook(book.id)"
          >
            <div class="flex gap-4">
              <img :src="book.cover || ''" :alt="book.title" class="h-32 w-24 rounded-2xl object-cover" />
              <div class="min-w-0 flex-1">
                <h3 class="line-clamp-2 text-lg font-semibold text-stone-900">{{ book.title }}</h3>
                <p class="mt-2 text-sm text-stone-500">{{ book.author || '作者待补充' }}</p>
                <p class="mt-2 text-xs text-amber-600">评分 {{ book.rating || book.score || '-' }}</p>
                <p class="mt-3 line-clamp-3 text-sm leading-6 text-stone-600">
                  {{ book.recommend_reason || book.description || '点击查看详情，快速判断是否适合现在开读。' }}
                </p>
              </div>
            </div>
          </article>
        </div>
      </section>

      <section v-else-if="showEmptyState" class="mt-8 rounded-[2rem] bg-white p-8 shadow-sm">
        <div class="text-center">
          <h2 class="text-2xl font-semibold">换个关键词试试</h2>
          <p class="mt-2 text-sm text-stone-500">
            当前没有找到 “{{ currentQuery }}” 的相关结果，可以换成更短的题材词、作者名或角色关键词再试一次。
          </p>
        </div>

        <div class="mt-8">
          <div class="mb-4">
            <h3 class="text-xl font-semibold">给你一些推荐</h3>
            <p class="mt-1 text-sm text-stone-500">没有直接结果时，先看看这些大家常点开的书。</p>
          </div>

          <div v-if="recommendations.length > 0" class="grid gap-5 sm:grid-cols-2 xl:grid-cols-4">
            <article
              v-for="book in recommendations"
              :key="`recommend-${book.id}`"
              class="cursor-pointer rounded-[1.5rem] border border-stone-100 bg-stone-50 p-3 transition hover:border-stone-300 hover:bg-white"
              @click="goBook(book.id)"
            >
              <img :src="book.cover || ''" :alt="book.title" class="aspect-[3/4] w-full rounded-[1.1rem] object-cover" />
              <h3 class="mt-3 line-clamp-1 text-sm font-semibold text-stone-900">{{ book.title }}</h3>
              <p class="mt-1 text-xs text-stone-500">{{ book.author || '作者待补充' }}</p>
              <p class="mt-2 line-clamp-2 text-xs leading-5 text-stone-600">
                {{ book.recommend_reason || book.home_recommendation_reason || '也许会合你的口味。' }}
              </p>
            </article>
          </div>

          <div v-else class="rounded-2xl bg-stone-50 p-6 text-center text-sm text-stone-500">
            推荐内容正在准备中
          </div>
        </div>
      </section>

      <section v-else class="mt-8 rounded-[2rem] bg-white p-8 shadow-sm">
        <div class="text-center">
          <h2 class="text-2xl font-semibold">开始找书</h2>
          <p class="mt-2 text-sm text-stone-500">
            先输入书名、作者或一个你此刻想看的题材词，比如“悬疑”“成长”“治愈”。
          </p>
        </div>
      </section>
    </main>
  </div>
</template>
