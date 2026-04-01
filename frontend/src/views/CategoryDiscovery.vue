<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { useRoute, useRouter } from 'vue-router'
import {
  getAllCategories,
  getHotTags,
  getMoreRecommendations,
  type HomeBookItem,
  type HomeCategoryItem,
  type HomeTagItem,
} from '@/api/home'
import {
  CATEGORY_NAVIGATION_ENTRIES,
  getCategoryEntry,
  resolveCategoryFilter,
  type CategoryEntryKey,
} from '@/constants/categoryNavigation'

type StatusFilterValue = 'all' | 'ongoing' | 'completed' | 'paused'

const router = useRouter()
const route = useRoute()

const categories = ref<HomeCategoryItem[]>([])
const tags = ref<HomeTagItem[]>([])
const books = ref<HomeBookItem[]>([])
const loading = ref(false)
const filtersReady = ref(false)
const total = ref(0)
const page = ref(1)
const pageSize = 12
const activeTagId = ref<number | null>(null)
const activeStatus = ref<StatusFilterValue>('all')

const statusOptions: Array<{ value: StatusFilterValue; label: string }> = [
  { value: 'all', label: '全部状态' },
  { value: 'completed', label: '已完结' },
  { value: 'ongoing', label: '连载中' },
  { value: 'paused', label: '暂停更新' },
]

const selectedEntry = computed(() => {
  const entry = typeof route.query.entry === 'string' ? route.query.entry : ''
  return getCategoryEntry(entry)
})

const resolvedFilter = computed(() => resolveCategoryFilter(selectedEntry.value, categories.value))

const effectiveCompletionStatus = computed(() => {
  if (activeStatus.value !== 'all') return activeStatus.value
  return resolvedFilter.value.completionStatus
})

const pageCount = computed(() => Math.max(1, Math.ceil(total.value / pageSize)))
const pageTitle = computed(() => (selectedEntry.value ? `${selectedEntry.value.label}分类` : '全部分类'))
const pageDescription = computed(() => {
  if (selectedEntry.value) {
    return `${selectedEntry.value.label}作品池已为你准备好，还可以继续叠加状态和标签筛选。`
  }
  return '按题材、风格和更新状态筛选作品，快速找到更符合口味的书。'
})

function parseNumberQuery(value: unknown) {
  if (typeof value !== 'string' || !value) return null
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : null
}

function parseStatusQuery(value: unknown): StatusFilterValue {
  if (value === 'ongoing' || value === 'completed' || value === 'paused') return value
  return 'all'
}

function parsePageQuery(value: unknown) {
  if (typeof value !== 'string' || !value) return 1
  const parsed = Number(value)
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : 1
}

function buildQuery(next: {
  entry?: string
  tag?: number | null
  status?: StatusFilterValue
  page?: number
}) {
  const query: Record<string, string> = {}

  if (next.entry) query.entry = next.entry
  if (next.tag) query.tag = String(next.tag)
  if (next.status && next.status !== 'all') query.status = next.status
  if ((next.page || 1) > 1) query.page = String(next.page)

  return query
}

function completionStatusText(status?: string) {
  if (status === 'completed') return '已完结'
  if (status === 'paused') return '暂停更新'
  return '连载中'
}

async function loadFilters() {
  try {
    const [categoriesRes, tagsRes] = await Promise.all([getAllCategories(), getHotTags()])
    categories.value = categoriesRes.items || []
    tags.value = tagsRes.items || []
  } catch {
    categories.value = []
    tags.value = []
    ElMessage.warning('分类筛选数据加载失败，已尽量展示可用内容')
  } finally {
    filtersReady.value = true
  }
}

async function loadBooks() {
  if (!filtersReady.value) return

  loading.value = true
  try {
    const res = await getMoreRecommendations({
      page: page.value,
      page_size: pageSize,
      category_id: resolvedFilter.value.categoryId,
      tag_id: activeTagId.value || undefined,
      completion_status: effectiveCompletionStatus.value,
      keyword: resolvedFilter.value.keyword,
    })
    books.value = res.items || []
    total.value = Number(res.pagination?.total || 0)
  } catch {
    books.value = []
    total.value = 0
    ElMessage.warning('分类作品加载失败，请稍后再试')
  } finally {
    loading.value = false
  }
}

async function replaceRoute(query: Record<string, string>) {
  await router.replace({
    path: '/categories',
    query,
  })
}

async function selectEntry(entryKey?: CategoryEntryKey) {
  await replaceRoute(
    buildQuery({
      entry: entryKey,
      tag: activeTagId.value,
      status: activeStatus.value,
      page: 1,
    })
  )
}

async function selectTag(tagId: number | null) {
  await replaceRoute(
    buildQuery({
      entry: selectedEntry.value?.key,
      tag: tagId,
      status: activeStatus.value,
      page: 1,
    })
  )
}

async function selectStatus(status: StatusFilterValue) {
  await replaceRoute(
    buildQuery({
      entry: selectedEntry.value?.key,
      tag: activeTagId.value,
      status,
      page: 1,
    })
  )
}

async function changePage(nextPage: number) {
  await replaceRoute(
    buildQuery({
      entry: selectedEntry.value?.key,
      tag: activeTagId.value,
      status: activeStatus.value,
      page: nextPage,
    })
  )
}

function goBook(bookId: number) {
  router.push(`/books/${bookId}`)
}

watch(
  [() => route.query.entry, () => route.query.tag, () => route.query.status, () => route.query.page, filtersReady],
  async () => {
    if (!filtersReady.value) return

    activeTagId.value = parseNumberQuery(route.query.tag)
    activeStatus.value = parseStatusQuery(route.query.status)
    page.value = parsePageQuery(route.query.page)
    await loadBooks()
  },
  { immediate: true }
)

onMounted(async () => {
  await loadFilters()
})
</script>

<template>
  <div class="min-h-screen bg-[linear-gradient(180deg,#f5f2ec_0%,#f1eee7_24%,#faf8f4_100%)] text-stone-900">
    <header class="sticky top-0 z-30 border-b border-stone-200 bg-white/92 backdrop-blur">
      <div class="mx-auto flex max-w-6xl items-center gap-3 px-4 py-3">
        <button
          class="rounded-full border border-stone-300 px-4 py-2 text-sm text-stone-700 transition hover:border-stone-500 hover:bg-stone-50"
          @click="router.push('/')"
        >
          返回首页
        </button>
        <div class="min-w-0 flex-1">
          <p class="truncate text-sm font-medium text-stone-900">{{ pageTitle }}</p>
          <p class="truncate text-xs text-stone-500">{{ pageDescription }}</p>
        </div>
      </div>
    </header>

    <main class="mx-auto max-w-6xl px-4 py-8">
      <section class="overflow-hidden rounded-[2rem] bg-[#171717] p-6 text-white shadow-lg shadow-stone-300/30 md:p-8">
        <div class="grid gap-6 lg:grid-cols-[minmax(0,1fr)_280px]">
          <div>
            <p class="text-sm uppercase tracking-[0.32em] text-stone-400">Category Discovery</p>
            <h1 class="mt-3 text-3xl font-semibold leading-tight md:text-4xl">{{ pageTitle }}</h1>
            <p class="mt-3 max-w-2xl text-sm leading-7 text-stone-300">
              按题材切入，再叠加标签和完结状态筛选，找书路径会更短，也更接近你的阅读偏好。
            </p>
          </div>

          <div class="rounded-[1.6rem] bg-white/8 p-5 backdrop-blur">
            <p class="text-xs uppercase tracking-[0.28em] text-stone-400">筛选提示</p>
            <ul class="mt-4 space-y-3 text-sm leading-6 text-stone-200">
              <li class="rounded-2xl bg-white/8 px-4 py-3">先选题材，再加状态或标签，结果会更精准。</li>
              <li class="rounded-2xl bg-white/8 px-4 py-3">完结、连载也作为独立入口，适合强目的性找书。</li>
              <li class="rounded-2xl bg-white/8 px-4 py-3">当前共找到 {{ total }} 本匹配作品。</li>
            </ul>
          </div>
        </div>
      </section>

      <section class="mt-8 rounded-[2rem] bg-white p-6 shadow-sm">
        <div class="flex flex-wrap items-center gap-3">
          <button
            class="rounded-full border px-4 py-2 text-sm transition"
            :class="!selectedEntry ? 'border-stone-900 bg-stone-900 text-white' : 'border-stone-300 bg-white text-stone-700'"
            @click="selectEntry()"
          >
            全部分类
          </button>

          <button
            v-for="item in CATEGORY_NAVIGATION_ENTRIES"
            :key="item.key"
            class="flex items-center gap-2 rounded-full border px-4 py-2 text-sm transition"
            :class="
              selectedEntry?.key === item.key ? 'border-stone-900 bg-stone-900 text-white' : 'border-stone-300 bg-white text-stone-700'
            "
            @click="selectEntry(item.key)"
          >
            <component :is="item.icon" class="h-4 w-4" />
            <span>{{ item.label }}</span>
          </button>
        </div>

        <div class="mt-6 grid gap-5 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <div>
            <p class="text-sm font-medium text-stone-900">状态筛选</p>
            <div class="mt-3 flex flex-wrap gap-3">
              <button
                v-for="item in statusOptions"
                :key="item.value"
                class="rounded-full border px-4 py-2 text-sm transition"
                :class="
                  activeStatus === item.value ? 'border-stone-900 bg-stone-900 text-white' : 'border-stone-300 bg-stone-50 text-stone-700'
                "
                @click="selectStatus(item.value)"
              >
                {{ item.label }}
              </button>
            </div>
          </div>

          <div>
            <p class="text-sm font-medium text-stone-900">继续筛选</p>
            <div class="mt-3 flex flex-wrap gap-3">
              <button
                class="rounded-full border px-4 py-2 text-sm transition"
                :class="activeTagId === null ? 'border-stone-900 bg-stone-900 text-white' : 'border-stone-300 bg-stone-50 text-stone-700'"
                @click="selectTag(null)"
              >
                全部标签
              </button>
              <button
                v-for="tag in tags"
                :key="tag.id"
                class="rounded-full border px-4 py-2 text-sm transition"
                :class="activeTagId === tag.id ? 'border-stone-900 bg-stone-900 text-white' : 'border-stone-300 bg-stone-50 text-stone-700'"
                @click="selectTag(tag.id)"
              >
                {{ tag.label }}
              </button>
            </div>
          </div>
        </div>
      </section>

      <section class="mt-8 rounded-[2rem] bg-white p-6 shadow-sm">
        <div class="mb-5 flex flex-wrap items-end justify-between gap-4">
          <div>
            <h2 class="text-2xl font-semibold">作品列表</h2>
            <p class="mt-1 text-sm text-stone-500">
              {{ selectedEntry ? `当前入口：${selectedEntry.label}` : '当前入口：全部分类' }}
              <span v-if="effectiveCompletionStatus"> · {{ completionStatusText(effectiveCompletionStatus) }}</span>
            </p>
          </div>

          <div class="text-sm text-stone-500">第 {{ page }} / {{ pageCount }} 页</div>
        </div>

        <div v-if="loading" class="rounded-2xl bg-stone-50 py-12 text-center text-sm text-stone-500">作品列表加载中...</div>

        <div v-else-if="books.length === 0" class="rounded-2xl bg-stone-50 px-6 py-12 text-center text-sm text-stone-500">
          当前筛选下暂时没有匹配作品，试试切换分类、标签或状态。
        </div>

        <template v-else>
          <div class="grid gap-5 sm:grid-cols-2 xl:grid-cols-4">
            <article
              v-for="book in books"
              :key="book.id"
              class="cursor-pointer rounded-[1.5rem] border border-stone-100 bg-stone-50 p-3 transition hover:-translate-y-0.5 hover:border-stone-300 hover:bg-white hover:shadow-sm"
              @click="goBook(book.id)"
            >
              <img :src="book.cover || ''" :alt="book.title" class="aspect-[3/4] w-full rounded-[1.1rem] object-cover" />

              <div class="mt-3 flex items-center justify-between gap-3">
                <h3 class="line-clamp-1 text-sm font-semibold text-stone-900">{{ book.title }}</h3>
                <span class="rounded-full bg-stone-200 px-2 py-1 text-[11px] text-stone-700">
                  {{ completionStatusText(book.completion_status) }}
                </span>
              </div>

              <p class="mt-1 text-xs text-stone-500">{{ book.author || '作者待补充' }}</p>
              <p class="mt-2 text-xs text-amber-600">评分 {{ book.rating || book.score || '-' }}</p>
              <p class="mt-3 line-clamp-2 min-h-10 text-xs leading-5 text-stone-600">
                {{ book.recommend_reason || book.home_recommendation_reason || book.description || '点击查看详情，判断是否适合现在开读。' }}
              </p>
            </article>
          </div>

          <div class="mt-6 flex items-center justify-end gap-2">
            <button
              class="rounded-full border border-stone-300 px-4 py-2 text-sm text-stone-700 transition disabled:cursor-not-allowed disabled:opacity-50"
              :disabled="page <= 1"
              @click="changePage(page - 1)"
            >
              上一页
            </button>
            <button
              class="rounded-full border border-stone-300 px-4 py-2 text-sm text-stone-700 transition disabled:cursor-not-allowed disabled:opacity-50"
              :disabled="page >= pageCount"
              @click="changePage(page + 1)"
            >
              下一页
            </button>
          </div>
        </template>
      </section>
    </main>
  </div>
</template>
