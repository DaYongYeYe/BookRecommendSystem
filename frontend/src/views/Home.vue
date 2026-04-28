<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { getToken } from '@/api/request'
import { getUserProfile, type UserProfile } from '@/api/user'
import { isCreatorToken } from '@/utils/auth'
import CategoryEntryGrid from '@/components/home/CategoryEntryGrid.vue'
import {
  getBookRankings,
  getBooksByCategoryOrTag,
  getContinueReading,
  getHighlightedCategories,
  getHomeRecommendations,
  getHotTags,
  getMoreRecommendations,
  type BookRankingItem,
  type BookRankingMeta,
  type BookRankingTypeOption,
  type HomeBookItem,
  type HomeCategoryItem,
  type HomeContinueReadingItem,
  type HomeTagItem,
} from '@/api/home'
import {
  DEFAULT_RANKING_TYPES,
  getRankingTypeMeta,
  normalizeRankingType,
  type BookRankingType,
} from '@/constants/bookRankings'

const router = useRouter()

const currentUser = ref<UserProfile | null>(null)
const defaultAvatar =
  'https://images.unsplash.com/photo-1438761681033-6461ffad8d80?auto=format&fit=crop&w=200&q=80'
const books = ref<HomeBookItem[]>([])
const categories = ref<HomeCategoryItem[]>([])
const tags = ref<HomeTagItem[]>([])
const rankingBooks = ref<BookRankingItem[]>([])
const continueReading = ref<HomeContinueReadingItem | null>(null)
const activeCategoryId = ref<number | null>(null)
const activeTagId = ref<number | null>(null)
const loadingBooks = ref(false)
const loadingRankings = ref(false)
const activeRankingType = ref<BookRankingType>('hot')
const rankingTypes = ref<BookRankingTypeOption[]>(DEFAULT_RANKING_TYPES)
const rankingMeta = ref<BookRankingMeta>(getRankingTypeMeta('hot'))

const heroBook = computed(() => continueReading.value || rankingBooks.value[0] || books.value[0] || null)
const canOpenCreator = computed(() => {
  if (currentUser.value?.role) return currentUser.value.role === 'creator'
  return isCreatorToken()
})
const rankingHero = computed(() => rankingBooks.value[0] || null)
const rankingList = computed(() => rankingBooks.value.slice(1))

function goBook(bookId: number) {
  router.push(`/books/${bookId}`)
}

function goReader(bookId: number) {
  router.push({ path: `/reader/${bookId}`, query: { resume: '1' } })
}

function goProfile() {
  if (!getToken()) {
    router.push('/login')
    return
  }
  router.push('/user/profile')
}

function goCreatorEntry() {
  router.push('/creator-center')
}

function goMoreRecommendations() {
  router.push('/recommendations')
}

function goRankings(type = activeRankingType.value) {
  router.push({ path: '/rankings', query: { type } })
}

function goSearchPage() {
  router.push('/search')
}

function formatReads(value?: number) {
  const num = Number(value || 0)
  if (!num) return '刚刚上架'
  if (num >= 10000) {
    return `${(num / 10000).toFixed(1)} 万人在读`
  }
  return `${num} 人在读`
}

function formatPercent(value?: number) {
  return `${Math.round(Number(value || 0))}%`
}

function formatCompactNumber(value?: number | null) {
  const num = Number(value || 0)
  if (num >= 10000) {
    return `${(num / 10000).toFixed(1)}万`
  }
  return `${num}`
}

function rankingBadgeClass(rank?: number) {
  if (rank === 1) return 'bg-[#171717] text-white'
  if (rank === 2) return 'bg-stone-200 text-stone-900'
  if (rank === 3) return 'bg-amber-100 text-amber-700'
  return 'bg-stone-100 text-stone-700'
}

async function loadHomeBooks() {
  loadingBooks.value = true
  try {
    if (activeCategoryId.value || activeTagId.value) {
      const res = await getBooksByCategoryOrTag({
        category_id: activeCategoryId.value || undefined,
        tag_id: activeTagId.value || undefined,
      })
      books.value = res.items || []
      return
    }
    if (getToken()) {
      const res = await getHomeRecommendations(8)
      books.value = res.items || []
      return
    }
    const res = await getMoreRecommendations({ page: 1, page_size: 8 })
    books.value = res.items || []
  } catch (_error) {
    books.value = []
    ElMessage.warning('推荐书籍加载失败，请稍后重试')
  } finally {
    loadingBooks.value = false
  }
}

async function loadRankingBooks(type = activeRankingType.value) {
  loadingRankings.value = true
  try {
    const res = await getBookRankings({ type, limit: 5 })
    activeRankingType.value = normalizeRankingType(res.type)
    rankingTypes.value = res.available_types?.length ? res.available_types : DEFAULT_RANKING_TYPES
    rankingMeta.value = res.meta || getRankingTypeMeta(activeRankingType.value)
    rankingBooks.value = res.items || []
  } catch (_error) {
    rankingBooks.value = []
    rankingMeta.value = getRankingTypeMeta(type)
    ElMessage.warning('榜单加载失败，请稍后重试')
  } finally {
    loadingRankings.value = false
  }
}

async function loadHomeData() {
  try {
    const [tagsRes, categoriesRes, continueRes] = await Promise.all([
      getHotTags(),
      getHighlightedCategories(),
      getContinueReading(),
    ])
    tags.value = tagsRes.items || []
    categories.value = categoriesRes.items || []
    continueReading.value = continueRes.item || null
  } catch (_error) {
    ElMessage.warning('首页数据加载不完整，已尽量展示可用内容')
  }

  await Promise.allSettled([loadHomeBooks(), loadRankingBooks()])
}

async function selectCategory(categoryId: number | null) {
  activeCategoryId.value = categoryId
  await loadHomeBooks()
}

async function selectTag(tagId: number | null) {
  activeTagId.value = tagId
  await loadHomeBooks()
}

async function selectRankingType(type: BookRankingType) {
  if (type === activeRankingType.value && rankingBooks.value.length) return
  activeRankingType.value = type
  await loadRankingBooks(type)
}

async function loadProfile() {
  if (!getToken()) return
  try {
    const res = await getUserProfile()
    currentUser.value = res.user
  } catch {
    currentUser.value = null
  }
}

onMounted(async () => {
  await Promise.allSettled([loadProfile(), loadHomeData()])
})
</script>

<template>
  <div class="min-h-screen bg-stone-100 text-stone-900">
    <header class="sticky top-0 z-30 border-b border-stone-200 bg-white/92 backdrop-blur">
      <div class="mx-auto flex max-w-6xl items-center gap-3 px-4 py-3">
        <button class="shrink-0 text-lg font-semibold tracking-tight text-stone-900" @click="router.push('/')">
          Book Recommend
        </button>

        <button
          class="flex min-w-0 flex-1 items-center gap-3 rounded-full border border-stone-200 bg-stone-50 px-4 py-3 text-left transition hover:border-stone-300 hover:bg-white"
          @click="goSearchPage"
        >
          <span class="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-stone-900 text-sm font-semibold text-white">
            搜
          </span>
          <div class="min-w-0">
            <p class="truncate text-sm font-medium text-stone-900">搜索书名 / 作者 / 标签 / 关键词</p>
            <p class="truncate text-xs text-stone-500">热门：悬疑、治愈、成长、古言</p>
          </div>
        </button>

        <div class="hidden items-center gap-2 md:flex">
          <button
            class="rounded-full border border-stone-300 px-4 py-2 text-sm text-stone-700 transition hover:border-stone-500"
            @click="router.push('/user/library')"
          >
            我的阅读
          </button>
          <button
            class="rounded-full border border-emerald-300 bg-emerald-50 px-4 py-2 text-sm text-emerald-700 transition hover:bg-emerald-100"
            @click="goCreatorEntry"
          >
            {{ canOpenCreator ? '进入创作中心' : '成为作者' }}
          </button>
        </div>

        <button class="flex shrink-0 items-center gap-2 rounded-full p-1 pr-3 transition hover:bg-stone-100" @click="goProfile">
          <img
            :src="currentUser?.avatar_url || defaultAvatar"
            alt="avatar"
            class="h-9 w-9 rounded-full object-cover"
          />
          <span class="hidden text-sm text-stone-700 sm:inline">{{ currentUser?.name || currentUser?.username || '去登录' }}</span>
        </button>
      </div>
    </header>

    <main class="mx-auto max-w-6xl px-4 py-8">
      <section class="overflow-hidden rounded-[2rem] bg-[#171717] p-8 text-white shadow-lg shadow-stone-300/40 md:p-12">
        <div class="grid gap-8 lg:grid-cols-[minmax(0,1fr)_280px] lg:items-end">
          <div>
            <p class="text-sm uppercase tracking-[0.32em] text-stone-400">Reader Home</p>
            <h1 class="mt-4 max-w-3xl text-4xl font-semibold leading-tight md:text-5xl">
              先找到今晚想看的那本书，再决定把时间交给谁。
            </h1>
            <p class="mt-4 max-w-2xl text-sm leading-7 text-stone-300 md:text-base">
              首页聚焦找书、继续阅读和快速决策。你可以从榜单、标签、分类和搜索入口一路点进详情，把“发现一本书”到“开始阅读”的距离再缩短一点。
            </p>

            <div class="mt-6 flex flex-wrap items-center gap-3">
              <button
                class="rounded-full bg-white px-6 py-3 text-sm font-medium text-stone-900 transition hover:bg-stone-200"
                @click="goSearchPage"
              >
                立即搜索
              </button>
              <button
                class="rounded-full border border-white/15 px-6 py-3 text-sm font-medium text-white transition hover:bg-white/10"
                @click="goCreatorEntry"
              >
                {{ canOpenCreator ? '进入创作中心' : '查看作者入口' }}
              </button>
            </div>
          </div>

          <div class="rounded-[1.75rem] bg-white/8 p-5 backdrop-blur">
            <p class="text-xs uppercase tracking-[0.28em] text-stone-400">Now Picking</p>
            <template v-if="heroBook">
              <img :src="heroBook.cover || ''" :alt="heroBook.title" class="mt-4 h-52 w-full rounded-[1.4rem] object-cover" />
              <h2 class="mt-4 line-clamp-2 text-2xl font-semibold">{{ heroBook.title }}</h2>
              <p class="mt-2 text-sm text-stone-300">{{ heroBook.author || '作者待补充' }}</p>
              <p class="mt-3 text-sm leading-6 text-stone-300">
                {{ heroBook.recommend_reason || heroBook.home_recommendation_reason || '值得先点开看看的第一本书。' }}
              </p>
              <button
                class="mt-5 rounded-full border border-white/15 px-4 py-2 text-sm text-white transition hover:bg-white/10"
                @click="goBook(heroBook.id)"
              >
                查看详情
              </button>
            </template>
            <template v-else>
              <div class="mt-4 rounded-[1.4rem] border border-dashed border-white/15 px-4 py-10 text-center text-sm text-stone-300">
                推荐内容正在准备中
              </div>
            </template>
          </div>
        </div>
      </section>

      <section v-if="continueReading" class="mt-8 rounded-[2rem] bg-white p-6 shadow-sm">
        <div class="flex flex-col gap-5 md:flex-row md:items-center">
          <img :src="continueReading.cover || ''" :alt="continueReading.title" class="h-36 w-24 rounded-2xl object-cover" />
          <div class="min-w-0 flex-1">
            <p class="text-sm text-stone-400">继续阅读</p>
            <h2 class="mt-2 text-2xl font-semibold">{{ continueReading.title }}</h2>
            <p class="mt-2 text-sm text-stone-500">
              {{ continueReading.section_title || '已为你保留上次阅读位置' }}
            </p>
            <p class="mt-2 text-sm text-stone-500">当前进度 {{ formatPercent(continueReading.scroll_percent) }}</p>
          </div>
          <div class="flex gap-3">
            <button class="rounded-full border border-stone-300 px-5 py-3 text-sm text-stone-700" @click="goBook(continueReading.id)">
              查看详情
            </button>
            <button class="rounded-full bg-stone-900 px-5 py-3 text-sm font-medium text-white" @click="goReader(continueReading.id)">
              继续阅读
            </button>
          </div>
        </div>
      </section>

      <CategoryEntryGrid />

      <section class="mt-10 rounded-[2rem] bg-white p-6 shadow-sm md:p-8">
        <div class="flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
          <div class="max-w-2xl">
            <button class="text-left" @click="goRankings()">
              <p class="text-sm uppercase tracking-[0.28em] text-stone-400">Rankings</p>
              <h2 class="mt-3 text-3xl font-semibold text-stone-900">{{ rankingMeta.label }}</h2>
            </button>
            <p class="mt-3 text-sm leading-7 text-stone-500">
              {{ rankingMeta.description }}
            </p>
          </div>

          <div class="flex flex-wrap gap-3">
            <span class="rounded-full bg-stone-100 px-4 py-2 text-xs text-stone-600">
              {{ rankingMeta.primary_metric }}
            </span>
            <span class="rounded-full bg-stone-100 px-4 py-2 text-xs text-stone-600">
              {{ rankingMeta.update_cycle }}
            </span>
            <button
              class="rounded-full border border-stone-300 px-4 py-2 text-sm font-medium text-stone-700 transition hover:border-stone-500 hover:bg-stone-50"
              @click="goRankings()"
            >
              更多榜单
            </button>
          </div>
        </div>

        <div class="mt-6 flex flex-wrap gap-3">
          <button
            v-for="item in rankingTypes"
            :key="item.key"
            class="rounded-full border px-4 py-2 text-sm transition"
            :class="
              activeRankingType === item.key
                ? 'border-stone-900 bg-stone-900 text-white'
                : 'border-stone-300 bg-white text-stone-700 hover:border-stone-400'
            "
            @click="selectRankingType(item.key)"
          >
            {{ item.label }}
          </button>
        </div>

        <div v-if="loadingRankings" class="mt-6 rounded-[1.75rem] bg-stone-50 px-6 py-14 text-center text-sm text-stone-500">
          榜单加载中...
        </div>

        <div v-else-if="rankingBooks.length === 0" class="mt-6 rounded-[1.75rem] bg-stone-50 px-6 py-14 text-center text-sm text-stone-500">
          暂时还没有可展示的榜单内容。
        </div>

        <div v-else class="mt-6 grid gap-5 lg:grid-cols-[minmax(0,1fr)_360px]">
          <button
            v-if="rankingHero"
            class="overflow-hidden rounded-[2rem] bg-stone-950 text-left text-white transition hover:-translate-y-0.5"
            @click="goBook(rankingHero.id)"
          >
            <div class="grid gap-6 p-6 md:grid-cols-[180px_minmax(0,1fr)] md:p-7">
              <img :src="rankingHero.cover || ''" :alt="rankingHero.title" class="h-64 w-full rounded-[1.5rem] object-cover" />
              <div>
                <div class="flex flex-wrap items-center gap-3">
                  <span class="rounded-full bg-white/12 px-4 py-2 text-sm font-semibold text-white">
                    TOP {{ rankingHero.rank }}
                  </span>
                  <span class="rounded-full bg-amber-200 px-4 py-2 text-sm font-medium text-amber-900">
                    {{ rankingHero.heat_label || rankingMeta.primary_metric }}
                  </span>
                </div>

                <h3 class="mt-5 line-clamp-2 text-3xl font-semibold">{{ rankingHero.title }}</h3>
                <p class="mt-3 text-sm text-stone-300">
                  {{ rankingHero.author || '作者待补充' }} · {{ rankingHero.category_name || '待分类' }}
                </p>
                <p class="mt-5 line-clamp-3 text-sm leading-7 text-stone-300">
                  {{ rankingHero.description || rankingHero.ranking_note || '当前主榜单中最值得优先点开的作品。' }}
                </p>

                <div class="mt-6 grid gap-3 sm:grid-cols-3">
                  <div class="rounded-2xl bg-white/8 px-4 py-4">
                    <p class="text-xs text-stone-400">在读热度</p>
                    <p class="mt-2 text-lg font-semibold text-white">{{ formatCompactNumber(rankingHero.recent_reads) }}</p>
                  </div>
                  <div class="rounded-2xl bg-white/8 px-4 py-4">
                    <p class="text-xs text-stone-400">书架收藏</p>
                    <p class="mt-2 text-lg font-semibold text-white">{{ formatCompactNumber(rankingHero.shelf_count) }}</p>
                  </div>
                  <div class="rounded-2xl bg-white/8 px-4 py-4">
                    <p class="text-xs text-stone-400">追更 / 增长</p>
                    <p class="mt-2 text-lg font-semibold text-white">
                      {{ formatCompactNumber(rankingHero.reading_users || rankingHero.recent_growth) }}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </button>

          <div class="space-y-3">
            <article
              v-for="item in rankingList"
              :key="`rank-${item.id}`"
              class="flex cursor-pointer items-center gap-4 rounded-[1.75rem] border border-stone-200 p-4 transition hover:border-stone-400 hover:bg-stone-50"
              @click="goBook(item.id)"
            >
              <div
                class="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl text-base font-semibold"
                :class="rankingBadgeClass(item.rank)"
              >
                {{ item.rank }}
              </div>
              <img :src="item.cover || ''" :alt="item.title" class="h-24 w-16 rounded-2xl object-cover" />
              <div class="min-w-0 flex-1">
                <div class="flex flex-wrap items-center gap-2">
                  <p class="line-clamp-1 text-base font-semibold text-stone-900">{{ item.title }}</p>
                  <span class="rounded-full bg-stone-100 px-3 py-1 text-xs text-stone-500">
                    {{ item.heat_label || rankingMeta.primary_metric }}
                  </span>
                </div>
                <p class="mt-2 text-sm text-stone-500">{{ item.author || '作者待补充' }} · {{ item.category_name || '待分类' }}</p>
                <p class="mt-3 line-clamp-2 text-sm leading-6 text-stone-600">
                  {{ item.description || item.ranking_note || '这本书在当前榜单里的表现同样亮眼。' }}
                </p>
              </div>
            </article>
          </div>
        </div>
      </section>

      <section class="mt-10">
        <div class="mb-5 flex flex-wrap items-center gap-3">
          <button
            class="rounded-full border px-4 py-2 text-sm transition"
            :class="activeTagId === null ? 'border-stone-900 bg-stone-900 text-white' : 'border-stone-300 bg-white text-stone-700'"
            @click="selectTag(null)"
          >
            全部标签
          </button>
          <button
            v-for="tag in tags"
            :key="tag.id"
            class="rounded-full border px-4 py-2 text-sm transition"
            :class="activeTagId === tag.id ? 'border-stone-900 bg-stone-900 text-white' : 'border-stone-300 bg-white text-stone-700'"
            @click="selectTag(tag.id)"
          >
            {{ tag.label }}
          </button>
        </div>

        <div class="mb-4 flex items-end justify-between gap-4">
          <div>
            <h2 class="text-2xl font-semibold">为你推荐</h2>
            <p class="mt-1 text-sm text-stone-500">从高频阅读题材里先挑出更值得点开的书。</p>
          </div>
          <button class="text-sm font-medium text-stone-700 transition hover:text-stone-900" @click="goMoreRecommendations">
            更多推荐 >
          </button>
        </div>

        <div v-if="loadingBooks" class="rounded-2xl bg-white p-6 text-center text-sm text-stone-500 shadow-sm">
          推荐书籍加载中...
        </div>

        <div v-else-if="books.length === 0" class="rounded-2xl bg-white p-8 text-center text-sm text-stone-500 shadow-sm">
          暂时没有匹配内容，试试切换标签或前往搜索页换一个关键词。
        </div>

        <div v-else class="grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
          <article
            v-for="book in books"
            :key="book.id"
            class="cursor-pointer rounded-[1.5rem] bg-white p-3 shadow-sm transition hover:-translate-y-0.5 hover:shadow-md"
            @click="goBook(book.id)"
          >
            <img :src="book.cover || ''" :alt="book.title" class="aspect-[3/4] w-full rounded-[1.1rem] object-cover" />
            <h3 class="mt-3 line-clamp-1 text-sm font-semibold text-stone-900">{{ book.title }}</h3>
            <p class="mt-1 text-xs text-stone-500">{{ book.author || '作者待补充' }}</p>
            <p class="mt-2 text-xs text-amber-600">评分 {{ book.rating || book.score || '-' }}</p>
            <p class="mt-1 text-xs text-stone-400">{{ formatReads(book.recent_reads) }}</p>
            <p class="mt-3 line-clamp-2 min-h-10 text-xs leading-5 text-stone-600">
              {{ book.recommend_reason || book.home_recommendation_reason || '高分口碑推荐' }}
            </p>
          </article>
        </div>
      </section>

      <section class="mt-10 rounded-[2rem] bg-white p-5 shadow-sm">
        <div class="mb-4 flex flex-wrap gap-3">
          <button
            class="rounded-full border px-4 py-2 text-sm transition"
            :class="
              activeCategoryId === null ? 'border-stone-900 bg-stone-900 text-white' : 'border-stone-300 bg-white text-stone-700'
            "
            @click="selectCategory(null)"
          >
            全部分类
          </button>
          <button
            v-for="item in categories"
            :key="item.id"
            class="rounded-full border px-4 py-2 text-sm transition"
            :class="
              activeCategoryId === item.id ? 'border-stone-900 bg-stone-900 text-white' : 'border-stone-300 bg-white text-stone-700'
            "
            @click="selectCategory(item.id)"
          >
            {{ item.name }}
          </button>
        </div>
        <p class="text-sm leading-7 text-stone-500">
          先按题材缩小范围，再进入搜索页补上更细的作者名、标签词和剧情关键词，找书会更快。
        </p>
      </section>
    </main>
  </div>
</template>
