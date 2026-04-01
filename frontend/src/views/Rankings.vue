<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { useRoute, useRouter } from 'vue-router'
import {
  getBookRankings,
  type BookRankingItem,
  type BookRankingMeta,
  type BookRankingTypeOption,
} from '@/api/home'
import {
  DEFAULT_RANKING_TYPES,
  getRankingTypeMeta,
  normalizeRankingType,
  type BookRankingType,
} from '@/constants/bookRankings'

const route = useRoute()
const router = useRouter()

const loading = ref(false)
const activeType = ref<BookRankingType>('hot')
const rankingTypes = ref<BookRankingTypeOption[]>(DEFAULT_RANKING_TYPES)
const rankingMeta = ref<BookRankingMeta>(getRankingTypeMeta('hot'))
const rankingBooks = ref<BookRankingItem[]>([])
const snapshotDate = ref('')

const topBooks = computed(() => rankingBooks.value.slice(0, 3))
const restBooks = computed(() => rankingBooks.value.slice(3))
const snapshotText = computed(() => (snapshotDate.value ? snapshotDate.value.replace(/-/g, '.') : '--'))

function formatCompactNumber(value?: number | null) {
  const num = Number(value || 0)
  if (num >= 10000) {
    return `${(num / 10000).toFixed(1)}万`
  }
  return `${num}`
}

function formatPublishedDays(value?: number | null) {
  if (!value) return '上架时间待补充'
  if (value <= 1) return '今日上架'
  return `${value} 天前上架`
}

function completionStatusText(status?: string) {
  if (status === 'completed') return '已完结'
  if (status === 'paused') return '暂停更新'
  return '连载中'
}

function goBook(bookId: number) {
  router.push(`/books/${bookId}`)
}

function goHome() {
  router.push('/')
}

function changeType(type: BookRankingType) {
  if (type === activeType.value && route.query.type === type) return
  router.push({ path: '/rankings', query: { type } })
}

async function loadRankings(type: BookRankingType) {
  loading.value = true
  try {
    const response = await getBookRankings({ type, limit: 20 })
    activeType.value = normalizeRankingType(response.type)
    rankingTypes.value = response.available_types?.length ? response.available_types : DEFAULT_RANKING_TYPES
    rankingMeta.value = response.meta || getRankingTypeMeta(activeType.value)
    rankingBooks.value = response.items || []
    snapshotDate.value = response.snapshot_date || ''
  } catch (_error) {
    rankingBooks.value = []
    rankingMeta.value = getRankingTypeMeta(type)
    ElMessage.warning('榜单加载失败，请稍后重试')
  } finally {
    loading.value = false
  }
}

watch(
  () => route.query.type,
  async (value) => {
    const nextType = normalizeRankingType(typeof value === 'string' ? value : null)
    activeType.value = nextType
    await loadRankings(nextType)
  },
  { immediate: true }
)
</script>

<template>
  <div class="min-h-screen bg-[linear-gradient(180deg,#f6f0e6_0%,#f3f4f6_22%,#ffffff_100%)] px-4 py-8 text-stone-900">
    <div class="mx-auto max-w-6xl">
      <section class="overflow-hidden rounded-[2rem] bg-[#171717] px-6 py-8 text-white shadow-lg shadow-stone-200/70 md:px-8 md:py-10">
        <div class="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
          <div class="max-w-3xl">
            <p class="text-xs uppercase tracking-[0.32em] text-stone-400">Book Rankings</p>
            <h1 class="mt-4 text-4xl font-semibold leading-tight md:text-5xl">{{ rankingMeta.label }}</h1>
            <p class="mt-4 text-sm leading-7 text-stone-300 md:text-base">
              {{ rankingMeta.description }}
            </p>
            <div class="mt-5 flex flex-wrap gap-3 text-xs text-stone-200">
              <span class="rounded-full border border-white/10 bg-white/5 px-4 py-2">
                主指标 · {{ rankingMeta.primary_metric }}
              </span>
              <span class="rounded-full border border-white/10 bg-white/5 px-4 py-2">
                {{ rankingMeta.update_cycle }}
              </span>
              <span class="rounded-full border border-white/10 bg-white/5 px-4 py-2">
                更新日期 · {{ snapshotText }}
              </span>
            </div>
          </div>

          <div class="flex flex-wrap gap-3">
            <button
              class="rounded-full border border-white/15 px-5 py-3 text-sm font-medium text-white transition hover:bg-white/10"
              @click="goHome"
            >
              返回首页
            </button>
            <button
              class="rounded-full bg-white px-5 py-3 text-sm font-medium text-stone-900 transition hover:bg-stone-200"
              @click="router.push('/recommendations')"
            >
              看更多推荐
            </button>
          </div>
        </div>
      </section>

      <section class="mt-6 rounded-[2rem] bg-white p-5 shadow-sm md:p-6">
        <div class="flex flex-wrap gap-3">
          <button
            v-for="item in rankingTypes"
            :key="item.key"
            class="rounded-full border px-4 py-2 text-sm transition"
            :class="
              activeType === item.key
                ? 'border-stone-900 bg-stone-900 text-white'
                : 'border-stone-300 bg-white text-stone-700 hover:border-stone-400'
            "
            @click="changeType(item.key)"
          >
            {{ item.label }}
          </button>
        </div>
        <div class="mt-4 flex flex-wrap items-center justify-between gap-3 text-sm text-stone-500">
          <p>{{ rankingMeta.period_hint || '日榜/周榜/月榜后续开放' }}</p>
          <p>当前展示 Top {{ rankingBooks.length || 20 }}</p>
        </div>
      </section>

      <section class="mt-6">
        <div v-if="loading" class="rounded-[2rem] bg-white px-6 py-16 text-center text-sm text-stone-500 shadow-sm">
          榜单加载中...
        </div>

        <div v-else-if="rankingBooks.length === 0" class="rounded-[2rem] bg-white px-6 py-16 text-center text-sm text-stone-500 shadow-sm">
          暂时还没有可展示的榜单内容。
        </div>

        <template v-else>
          <div class="grid gap-5 lg:grid-cols-3">
            <article
              v-for="book in topBooks"
              :key="`top-${book.id}`"
              class="cursor-pointer overflow-hidden rounded-[2rem] bg-white shadow-sm transition hover:-translate-y-1 hover:shadow-lg"
              @click="goBook(book.id)"
            >
              <div class="relative">
                <img :src="book.cover || ''" :alt="book.title" class="aspect-[4/5] w-full object-cover" />
                <div class="absolute left-4 top-4 rounded-full bg-stone-950/85 px-4 py-2 text-sm font-semibold text-white">
                  TOP {{ book.rank }}
                </div>
              </div>
              <div class="p-5">
                <div class="flex flex-wrap items-center gap-2">
                  <span class="rounded-full bg-amber-100 px-3 py-1 text-xs font-medium text-amber-700">
                    {{ book.heat_label || rankingMeta.primary_metric }}
                  </span>
                  <span class="rounded-full bg-stone-100 px-3 py-1 text-xs text-stone-500">
                    {{ book.category_name || '待分类' }}
                  </span>
                </div>
                <h2 class="mt-4 line-clamp-2 text-2xl font-semibold text-stone-900">{{ book.title }}</h2>
                <p class="mt-2 text-sm text-stone-500">{{ book.author || '作者待补充' }}</p>
                <p class="mt-4 line-clamp-3 text-sm leading-7 text-stone-600">
                  {{ book.description || book.ranking_note || '这本书最近的表现很亮眼，值得先点开看看。' }}
                </p>

                <div class="mt-5 grid grid-cols-2 gap-3 text-sm text-stone-600">
                  <div class="rounded-2xl bg-stone-50 px-4 py-3">
                    <p class="text-xs text-stone-400">在读热度</p>
                    <p class="mt-2 font-semibold text-stone-900">{{ formatCompactNumber(book.recent_reads) }}</p>
                  </div>
                  <div class="rounded-2xl bg-stone-50 px-4 py-3">
                    <p class="text-xs text-stone-400">收藏 / 追更</p>
                    <p class="mt-2 font-semibold text-stone-900">
                      {{ formatCompactNumber(book.shelf_count || book.reading_users) }}
                    </p>
                  </div>
                </div>
              </div>
            </article>
          </div>

          <section class="mt-6 rounded-[2rem] bg-white p-5 shadow-sm md:p-6">
            <div class="mb-5 flex items-center justify-between gap-3">
              <div>
                <h2 class="text-2xl font-semibold">完整榜单</h2>
                <p class="mt-1 text-sm text-stone-500">继续往下看，快速判断哪些书更值得点开。</p>
              </div>
              <span class="rounded-full bg-stone-100 px-4 py-2 text-xs text-stone-600">
                {{ rankingMeta.label }} · Top {{ rankingBooks.length }}
              </span>
            </div>

            <div class="space-y-3">
              <article
                v-for="book in restBooks"
                :key="`rest-${book.id}`"
                class="grid cursor-pointer gap-4 rounded-[1.75rem] border border-stone-200 p-4 transition hover:border-stone-400 hover:bg-stone-50 md:grid-cols-[70px_96px_minmax(0,1fr)]"
                @click="goBook(book.id)"
              >
                <div class="flex items-center justify-center text-2xl font-semibold text-stone-900">
                  {{ book.rank }}
                </div>
                <img :src="book.cover || ''" :alt="book.title" class="h-32 w-24 rounded-2xl object-cover" />
                <div class="min-w-0">
                  <div class="flex flex-wrap items-center gap-2">
                    <h3 class="line-clamp-1 text-lg font-semibold text-stone-900">{{ book.title }}</h3>
                    <span class="rounded-full bg-stone-100 px-3 py-1 text-xs text-stone-600">
                      {{ completionStatusText(book.completion_status) }}
                    </span>
                  </div>
                  <p class="mt-2 text-sm text-stone-500">
                    {{ book.author || '作者待补充' }} · {{ book.category_name || '待分类' }}
                  </p>
                  <p class="mt-3 flex flex-wrap gap-2 text-xs text-stone-500">
                    <span class="rounded-full bg-amber-50 px-3 py-1 text-amber-700">
                      {{ book.heat_label || rankingMeta.primary_metric }}
                    </span>
                    <span class="rounded-full bg-stone-100 px-3 py-1">
                      收藏 {{ formatCompactNumber(book.shelf_count) }}
                    </span>
                    <span class="rounded-full bg-stone-100 px-3 py-1">
                      在读 {{ formatCompactNumber(book.reading_users || book.recent_reads) }}
                    </span>
                    <span v-if="book.published_days" class="rounded-full bg-stone-100 px-3 py-1">
                      {{ formatPublishedDays(book.published_days) }}
                    </span>
                  </p>
                  <p class="mt-3 line-clamp-2 text-sm leading-7 text-stone-600">
                    {{ book.description || book.ranking_note || '这本书在当前榜单里的表现很突出。' }}
                  </p>
                </div>
              </article>
            </div>
          </section>
        </template>
      </section>
    </div>
  </div>
</template>
