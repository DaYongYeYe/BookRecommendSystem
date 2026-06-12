<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { getToken } from '@/api/request'
import { USER_PROFILE_HUB_ROUTE_NAME } from '@/constants/routes'
import { DEFAULT_AVATAR_URL } from '@/utils/profile'
import { useUserProfileStore } from '@/stores/userProfile'
import { isCreatorToken } from '@/utils/auth'
import AppLogo from '@/components/AppLogo.vue'
import CategoryEntryGrid from '@/components/home/CategoryEntryGrid.vue'
import {
  getBookRankings,
  getHighlightedCategories,
  getHotTags,
  getRecommendationFeed,
  submitRecommendationFeedback,
  type BookRankingItem,
  type HomeBookItem,
  type HomeCategoryItem,
  type HomeTagItem,
  type RecommendationFeedSection,
  type RecommendationFeedbackPayload,
} from '@/api/home'
import { DEFAULT_RANKING_TYPES, normalizeRankingType, type BookRankingType } from '@/constants/bookRankings'

const router = useRouter()
const userProfileStore = useUserProfileStore()

const defaultAvatar = DEFAULT_AVATAR_URL
const currentUser = computed(() => userProfileStore.profile)
const categories = ref<HomeCategoryItem[]>([])
const tags = ref<HomeTagItem[]>([])
const feedSections = ref<RecommendationFeedSection[]>([])
const rankingBooks = ref<BookRankingItem[]>([])
const activeRankingType = ref<BookRankingType>('hot')
const loadingFeed = ref(false)
const loadingRankings = ref(false)

const canOpenCreator = computed(() => {
  if (currentUser.value) return currentUser.value.is_creator === true
  return isCreatorToken()
})
const continueSection = computed(() => sectionByKey('continue_reading'))
const todaySection = computed(() => sectionByKey('picked_for_you'))
const popularSection = computed(() => sectionByKey('popular_now'))
const tasteSection = computed(() => sectionByKey('same_category'))
const newSection = computed(() => sectionByKey('new_or_surging'))
const completedSection = computed(() => sectionByKey('completed_good_reads'))
const noteStats = computed(() => {
  const all = feedSections.value.flatMap((section) => section.items)
  const shelfCount = all.filter((book) => book.in_shelf).length
  const hiddenCount = all.filter((book) => book.feedback_state === 'hide').length
  const reasonCount = all.filter((book) => book.reason || book.recommend_reason).length
  return { shelfCount, hiddenCount, reasonCount }
})

function sectionByKey(key: string) {
  return feedSections.value.find((section) => section.key === key) || { key, title: '', description: '', items: [] }
}

function goBook(bookId: number) {
  router.push(`/books/${bookId}`)
}

function goReader(bookId: number) {
  router.push({ path: `/reader/${bookId}`, query: { resume: '1' } })
}

function goSearchPage() {
  router.push('/search')
}

function goProfile() {
  if (!getToken()) {
    router.push('/login')
    return
  }
  router.push({ name: USER_PROFILE_HUB_ROUTE_NAME })
}

function goCreatorEntry() {
  router.push('/creator-center')
}

function goRankings(type = activeRankingType.value) {
  router.push({ path: '/rankings', query: { type } })
}

function formatReads(value?: number | null) {
  const num = Number(value || 0)
  if (!num) return '新近上架'
  if (num >= 10000) return `${(num / 10000).toFixed(1)} 万人在读`
  return `${num} 人在读`
}

function formatScore(book: HomeBookItem) {
  return book.rating || book.score || book.metrics?.rating || '-'
}

function getReason(book: HomeBookItem) {
  return book.reason || book.recommend_reason || book.home_recommendation_reason || '基于评分、热度和题材为你推荐'
}

function getReads(book: HomeBookItem) {
  return book.metrics?.recent_reads || book.recent_reads || 0
}

function compactNumber(value?: number | null) {
  const num = Number(value || 0)
  if (num >= 10000) return `${(num / 10000).toFixed(1)}万`
  return `${num}`
}

function updateBookInFeed(bookId: number, updater: (book: HomeBookItem) => HomeBookItem | null) {
  feedSections.value = feedSections.value.map((section) => ({
    ...section,
    items: section.items
      .map((book) => (book.id === bookId ? updater(book) : book))
      .filter((book): book is HomeBookItem => Boolean(book)),
  }))
}

async function handleFeedback(book: HomeBookItem, action: RecommendationFeedbackPayload['action']) {
  if (!getToken()) {
    router.push({ path: '/login', query: { redirect: '/' } })
    return
  }
  try {
    await submitRecommendationFeedback({
      book_id: book.id,
      action,
      source_section: book.source_section || null,
    })
    if (action === 'hide') {
      updateBookInFeed(book.id, () => null)
      ElMessage.success('已减少类似推荐')
    } else {
      updateBookInFeed(book.id, (item) => ({
        ...item,
        in_shelf: action === 'add_to_shelf' ? true : item.in_shelf,
        feedback_state: action,
      }))
      ElMessage.success(action === 'more_like_this' ? '会多推荐类似作品' : action === 'add_to_shelf' ? '已加入书架' : '已稍后再读')
    }
  } catch (_error) {
    ElMessage.error('反馈保存失败，请稍后重试')
  }
}

async function loadFeed() {
  loadingFeed.value = true
  try {
    const res = await getRecommendationFeed(6)
    feedSections.value = res.sections || []
  } catch (_error) {
    feedSections.value = []
    ElMessage.warning('推荐流加载失败，请稍后重试')
  } finally {
    loadingFeed.value = false
  }
}

async function loadRankings(type = activeRankingType.value) {
  loadingRankings.value = true
  try {
    const res = await getBookRankings({ type, limit: 6 })
    activeRankingType.value = normalizeRankingType(res.type)
    rankingBooks.value = res.items || []
  } catch (_error) {
    rankingBooks.value = []
    ElMessage.warning('榜单加载失败，请稍后重试')
  } finally {
    loadingRankings.value = false
  }
}

async function loadMeta() {
  try {
    const [tagsRes, categoriesRes] = await Promise.all([getHotTags(), getHighlightedCategories()])
    tags.value = tagsRes.items || []
    categories.value = categoriesRes.items || []
  } catch (_error) {
    ElMessage.warning('首页标签与分类加载不完整')
  }
}

async function loadProfile() {
  if (!getToken()) return
  try {
    await userProfileStore.fetchProfile()
  } catch {
    userProfileStore.clearProfile()
  }
}

onMounted(async () => {
  await Promise.allSettled([loadProfile(), loadMeta(), loadFeed(), loadRankings()])
})
</script>

<template>
  <div class="min-h-screen bg-[#f5f3ef] text-stone-900">
    <header class="sticky top-0 z-30 border-b border-stone-200 bg-white/95 backdrop-blur">
      <div class="mx-auto flex max-w-6xl items-center gap-3 px-4 py-3">
        <button class="shrink-0" aria-label="返回阿书铺子首页" @click="router.push('/')">
          <AppLogo />
        </button>
        <button
          class="flex min-w-0 flex-1 items-center gap-3 rounded-full border border-stone-200 bg-stone-50 px-4 py-3 text-left transition hover:border-stone-300 hover:bg-white"
          @click="goSearchPage"
        >
          <span class="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-stone-900 text-sm font-semibold text-white">搜</span>
          <span class="min-w-0">
            <span class="block truncate text-sm font-medium">搜索书名 / 作者 / 标签 / 关键词</span>
            <span class="block truncate text-xs text-stone-500">热门：{{ tags.slice(0, 4).map((tag) => tag.label).join('、') || '悬疑、治愈、成长、古言' }}</span>
          </span>
        </button>
        <div class="hidden items-center gap-2 md:flex">
          <button class="rounded-full border border-stone-300 px-4 py-2 text-sm text-stone-700 transition hover:border-stone-500" @click="router.push('/user/library')">
            我的阅读
          </button>
          <button class="rounded-full border border-stone-300 px-4 py-2 text-sm text-stone-700 transition hover:border-stone-500" @click="router.push('/community')">
            书评广场
          </button>
          <button class="rounded-full border border-emerald-300 bg-emerald-50 px-4 py-2 text-sm text-emerald-700 transition hover:bg-emerald-100" @click="goCreatorEntry">
            {{ canOpenCreator ? '进入创作中心' : '成为作者' }}
          </button>
        </div>
        <button class="flex shrink-0 items-center gap-2 rounded-full p-1 pr-3 transition hover:bg-stone-100" @click="goProfile">
          <img :src="currentUser?.avatar_url || defaultAvatar" alt="avatar" class="h-9 w-9 rounded-full object-cover" />
          <span class="hidden text-sm text-stone-700 sm:inline">{{ currentUser?.name || currentUser?.username || '去登录' }}</span>
        </button>
      </div>
    </header>

    <main class="mx-auto max-w-6xl px-4 py-8">
      <section class="grid gap-5 lg:grid-cols-[minmax(0,1.25fr)_minmax(320px,0.75fr)]">
        <div class="rounded-[1.75rem] bg-white p-6 shadow-sm md:p-8">
          <p class="text-sm font-medium text-stone-500">今天继续读什么</p>
          <template v-if="continueSection.items.length">
            <div v-for="book in continueSection.items.slice(0, 1)" :key="book.id" class="mt-5 grid gap-5 md:grid-cols-[130px_minmax(0,1fr)]">
              <img :src="book.cover || ''" :alt="book.title" class="h-44 w-full rounded-2xl object-cover shadow-sm" />
              <div class="min-w-0">
                <h1 class="line-clamp-2 text-3xl font-semibold leading-tight">{{ book.title }}</h1>
                <p class="mt-2 text-sm text-stone-500">{{ book.author || '作者待补充' }} · {{ book.category_name || '继续上次阅读' }}</p>
                <p class="mt-4 line-clamp-2 text-sm leading-7 text-stone-600">{{ getReason(book) }}</p>
                <div class="mt-5 flex flex-wrap gap-3">
                  <button class="rounded-full bg-stone-900 px-6 py-3 text-sm font-medium text-white transition hover:bg-stone-700" @click="goReader(book.id)">
                    继续阅读
                  </button>
                  <button class="rounded-full border border-stone-300 px-6 py-3 text-sm text-stone-700 transition hover:border-stone-500" @click="goBook(book.id)">
                    查看详情
                  </button>
                </div>
              </div>
            </div>
          </template>
          <template v-else>
            <div class="mt-5 rounded-2xl border border-dashed border-stone-300 bg-stone-50 px-5 py-8">
              <h1 class="text-3xl font-semibold leading-tight">从一本值得停留的书开始。</h1>
              <p class="mt-3 max-w-2xl text-sm leading-7 text-stone-600">这里会优先显示你的续读记录。暂时没有记录时，可以先从今日推荐、榜单或搜索进入。</p>
              <button class="mt-5 rounded-full bg-stone-900 px-6 py-3 text-sm font-medium text-white" @click="goSearchPage">去找书</button>
            </div>
          </template>
        </div>

        <aside class="grid gap-4 rounded-[1.75rem] bg-[#17211d] p-6 text-white shadow-sm">
          <div>
            <p class="text-sm text-stone-300">阅读沉淀</p>
            <h2 class="mt-2 text-2xl font-semibold">让推荐跟着你的选择变聪明。</h2>
          </div>
          <div class="grid grid-cols-3 gap-3">
            <div class="rounded-2xl bg-white/10 p-4">
              <p class="text-xs text-stone-300">推荐理由</p>
              <p class="mt-2 text-2xl font-semibold">{{ noteStats.reasonCount }}</p>
            </div>
            <div class="rounded-2xl bg-white/10 p-4">
              <p class="text-xs text-stone-300">已在书架</p>
              <p class="mt-2 text-2xl font-semibold">{{ noteStats.shelfCount }}</p>
            </div>
            <div class="rounded-2xl bg-white/10 p-4">
              <p class="text-xs text-stone-300">已过滤</p>
              <p class="mt-2 text-2xl font-semibold">{{ noteStats.hiddenCount }}</p>
            </div>
          </div>
          <p class="text-sm leading-7 text-stone-300">点击“不感兴趣”会减少同类推荐，“类似更多”会提高相近分类与标签的权重。</p>
        </aside>
      </section>

      <section class="mt-8">
        <div class="mb-4 flex items-end justify-between gap-4">
          <div>
            <p class="text-sm font-medium text-stone-500">Picked for you</p>
            <h2 class="mt-1 text-2xl font-semibold">{{ todaySection.title || '今日推荐' }}</h2>
          </div>
          <button class="text-sm font-medium text-stone-700 hover:text-stone-950" @click="router.push('/recommendations')">更多推荐</button>
        </div>
        <div v-if="loadingFeed" class="rounded-2xl bg-white p-8 text-center text-sm text-stone-500 shadow-sm">推荐流加载中...</div>
        <div v-else class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <article
            v-for="book in todaySection.items"
            :key="`today-${book.id}`"
            class="group flex cursor-pointer gap-4 rounded-2xl bg-white p-4 shadow-sm transition hover:-translate-y-0.5 hover:shadow-md"
            @click="goBook(book.id)"
          >
            <img :src="book.cover || ''" :alt="book.title" class="h-36 w-24 shrink-0 rounded-xl object-cover" />
            <div class="min-w-0 flex-1">
              <div class="flex flex-wrap gap-2">
                <span v-if="book.category_name" class="rounded-full bg-stone-100 px-2.5 py-1 text-xs text-stone-600">{{ book.category_name }}</span>
                <span v-if="book.in_shelf" class="rounded-full bg-emerald-50 px-2.5 py-1 text-xs text-emerald-700">已在书架</span>
              </div>
              <h3 class="mt-3 line-clamp-1 text-base font-semibold">{{ book.title }}</h3>
              <p class="mt-1 text-xs text-stone-500">{{ book.author || '作者待补充' }} · 评分 {{ formatScore(book) }}</p>
              <p class="mt-3 line-clamp-2 text-sm leading-6 text-stone-600">{{ getReason(book) }}</p>
              <div class="mt-3 flex flex-wrap gap-2">
                <button class="rounded-full bg-stone-900 px-3 py-1.5 text-xs text-white" @click.stop="handleFeedback(book, 'more_like_this')">类似更多</button>
                <button class="rounded-full border border-stone-300 px-3 py-1.5 text-xs text-stone-600" @click.stop="handleFeedback(book, 'hide')">不感兴趣</button>
              </div>
            </div>
          </article>
        </div>
      </section>

      <section class="mt-10 grid gap-6 lg:grid-cols-[minmax(0,1fr)_360px]">
        <div class="rounded-[1.75rem] bg-white p-6 shadow-sm">
          <div class="flex items-center justify-between gap-4">
            <div>
              <p class="text-sm font-medium text-stone-500">Rankings</p>
              <h2 class="mt-1 text-2xl font-semibold">榜单精选</h2>
            </div>
            <div class="flex flex-wrap gap-2">
              <button
                v-for="item in DEFAULT_RANKING_TYPES.slice(0, 3)"
                :key="item.key"
                class="rounded-full border px-3 py-1.5 text-xs transition"
                :class="activeRankingType === item.key ? 'border-stone-900 bg-stone-900 text-white' : 'border-stone-300 text-stone-600'"
                @click="activeRankingType = item.key; loadRankings(item.key)"
              >
                {{ item.label }}
              </button>
            </div>
          </div>
          <div v-if="loadingRankings" class="mt-5 rounded-2xl bg-stone-50 p-8 text-center text-sm text-stone-500">榜单加载中...</div>
          <div v-else class="mt-5 space-y-3">
            <article
              v-for="book in rankingBooks.slice(0, 5)"
              :key="`rank-${book.id}`"
              class="flex cursor-pointer items-center gap-4 rounded-2xl border border-stone-100 p-3 transition hover:border-stone-300 hover:bg-stone-50"
              @click="goBook(book.id)"
            >
              <span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-stone-900 text-sm font-semibold text-white">{{ book.rank }}</span>
              <img :src="book.cover || ''" :alt="book.title" class="h-20 w-14 rounded-xl object-cover" />
              <div class="min-w-0 flex-1">
                <h3 class="truncate text-sm font-semibold">{{ book.title }}</h3>
                <p class="mt-1 text-xs text-stone-500">{{ book.author || '作者待补充' }} · {{ book.category_name || '待分类' }}</p>
                <p class="mt-2 text-xs text-amber-700">{{ book.heat_label || '综合热度' }}</p>
              </div>
            </article>
          </div>
          <button class="mt-5 rounded-full border border-stone-300 px-4 py-2 text-sm text-stone-700" @click="goRankings()">查看完整榜单</button>
        </div>

        <div class="rounded-[1.75rem] bg-white p-6 shadow-sm">
          <p class="text-sm font-medium text-stone-500">大家都在读</p>
          <h2 class="mt-1 text-2xl font-semibold">{{ popularSection.title || '近期热读' }}</h2>
          <div class="mt-5 space-y-4">
            <button
              v-for="book in popularSection.items.slice(0, 4)"
              :key="`popular-${book.id}`"
              class="flex w-full items-start gap-3 rounded-2xl border border-stone-100 p-3 text-left transition hover:border-stone-300 hover:bg-stone-50"
              @click="goBook(book.id)"
            >
              <img :src="book.cover || ''" :alt="book.title" class="h-20 w-14 rounded-xl object-cover" />
              <span class="min-w-0 flex-1">
                <span class="block truncate text-sm font-semibold">{{ book.title }}</span>
                <span class="mt-1 block text-xs text-stone-500">{{ formatReads(getReads(book)) }}</span>
                <span class="mt-2 block line-clamp-2 text-xs leading-5 text-stone-600">{{ getReason(book) }}</span>
              </span>
            </button>
          </div>
        </div>
      </section>

      <CategoryEntryGrid />

      <section class="mt-10 grid gap-6 lg:grid-cols-2">
        <section class="rounded-[1.75rem] bg-white p-6 shadow-sm">
          <div class="flex items-end justify-between gap-4">
            <div>
              <p class="text-sm font-medium text-stone-500">Taste extension</p>
              <h2 class="mt-1 text-2xl font-semibold">{{ tasteSection.title || '延续你的口味' }}</h2>
            </div>
          </div>
          <div class="mt-5 grid gap-4 sm:grid-cols-2">
            <button
              v-for="book in tasteSection.items.slice(0, 4)"
              :key="`taste-${book.id}`"
              class="rounded-2xl border border-stone-100 p-3 text-left transition hover:border-stone-300 hover:bg-stone-50"
              @click="goBook(book.id)"
            >
              <div class="flex gap-3">
                <img :src="book.cover || ''" :alt="book.title" class="h-24 w-16 rounded-xl object-cover" />
                <span class="min-w-0">
                  <span class="block truncate text-sm font-semibold">{{ book.title }}</span>
                  <span class="mt-1 block text-xs text-stone-500">{{ book.category_name || '同类推荐' }}</span>
                  <span class="mt-2 block line-clamp-2 text-xs leading-5 text-stone-600">{{ getReason(book) }}</span>
                </span>
              </div>
            </button>
          </div>
        </section>

        <section class="rounded-[1.75rem] bg-white p-6 shadow-sm">
          <div class="flex items-end justify-between gap-4">
            <div>
              <p class="text-sm font-medium text-stone-500">Completed reads</p>
              <h2 class="mt-1 text-2xl font-semibold">{{ completedSection.title || '完结好书' }}</h2>
            </div>
          </div>
          <div class="mt-5 grid gap-4 sm:grid-cols-2">
            <button
              v-for="book in completedSection.items.slice(0, 4)"
              :key="`completed-${book.id}`"
              class="rounded-2xl border border-stone-100 p-3 text-left transition hover:border-stone-300 hover:bg-stone-50"
              @click="goBook(book.id)"
            >
              <div class="flex gap-3">
                <img :src="book.cover || ''" :alt="book.title" class="h-24 w-16 rounded-xl object-cover" />
                <span class="min-w-0">
                  <span class="block truncate text-sm font-semibold">{{ book.title }}</span>
                  <span class="mt-1 block text-xs text-stone-500">评分 {{ formatScore(book) }} · {{ compactNumber(getReads(book)) }} 在读</span>
                  <span class="mt-2 block line-clamp-2 text-xs leading-5 text-stone-600">{{ getReason(book) }}</span>
                </span>
              </div>
            </button>
          </div>
        </section>
      </section>

      <section class="mt-10 rounded-[1.75rem] bg-white p-6 shadow-sm">
        <div class="flex flex-wrap items-center gap-3">
          <span class="text-sm font-medium text-stone-500">热门标签</span>
          <button
            v-for="tag in tags.slice(0, 12)"
            :key="tag.id"
            class="rounded-full border border-stone-200 px-4 py-2 text-sm text-stone-700 transition hover:border-stone-400 hover:bg-stone-50"
            @click="router.push({ path: '/search', query: { q: tag.label } })"
          >
            {{ tag.label }}
          </button>
        </div>
        <div class="mt-4 flex flex-wrap items-center gap-3">
          <span class="text-sm font-medium text-stone-500">精选分类</span>
          <button
            v-for="category in categories.slice(0, 10)"
            :key="category.id"
            class="rounded-full border border-stone-200 px-4 py-2 text-sm text-stone-700 transition hover:border-stone-400 hover:bg-stone-50"
            @click="router.push({ path: '/categories', query: { category_id: category.id } })"
          >
            {{ category.name }}
          </button>
        </div>
        <div class="mt-5 flex flex-wrap items-center justify-between gap-3 rounded-2xl bg-stone-50 px-4 py-4">
          <div>
            <p class="text-sm font-semibold text-stone-900">书单 / 书评广场</p>
            <p class="mt-1 text-xs text-stone-500">查看读者整理的主题书单，也可以发布自己的书评。</p>
          </div>
          <button class="rounded-full bg-stone-900 px-4 py-2 text-sm font-medium text-white" @click="router.push('/community')">进入广场</button>
        </div>
      </section>

      <section v-if="newSection.items.length" class="mt-10 rounded-[1.75rem] bg-[#201f1c] p-6 text-white shadow-sm">
        <p class="text-sm text-stone-300">{{ newSection.description }}</p>
        <h2 class="mt-1 text-2xl font-semibold">{{ newSection.title }}</h2>
        <div class="mt-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <button
            v-for="book in newSection.items.slice(0, 4)"
            :key="`new-${book.id}`"
            class="rounded-2xl bg-white/8 p-3 text-left transition hover:bg-white/12"
            @click="goBook(book.id)"
          >
            <img :src="book.cover || ''" :alt="book.title" class="aspect-[3/4] w-full rounded-xl object-cover" />
            <span class="mt-3 block line-clamp-1 text-sm font-semibold">{{ book.title }}</span>
            <span class="mt-1 block text-xs text-stone-300">{{ getReason(book) }}</span>
          </button>
        </div>
      </section>
    </main>
  </div>
</template>
