<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { getToken } from '@/api/request'
import { getUserProfile, type UserProfile } from '@/api/user'
import {
  getBookRankings,
  getBooksByCategoryOrTag,
  getHighlightedCategories,
  getHomeRecommendations,
  getHotTags,
  getMoreRecommendations,
  type HomeBookItem,
  type HomeCategoryItem,
  type HomeTagItem,
} from '@/api/home'

const router = useRouter()

const currentUser = ref<UserProfile | null>(null)
const defaultAvatar =
  'https://images.unsplash.com/photo-1438761681033-6461ffad8d80?auto=format&fit=crop&w=200&q=80'
const books = ref<HomeBookItem[]>([])
const categories = ref<HomeCategoryItem[]>([])
const tags = ref<HomeTagItem[]>([])
const rankingBooks = ref<HomeBookItem[]>([])
const activeCategoryId = ref<number | null>(null)
const activeTagId = ref<number | null>(null)
const loadingBooks = ref(false)

const heroBook = computed(() => rankingBooks.value[0] || books.value[0] || null)

function goBook(bookId: number) {
  router.push(`/books/${bookId}`)
}

function goProfile() {
  if (!getToken()) {
    router.push('/login')
    return
  }
  router.push('/user/profile')
}

function goMoreRecommendations() {
  router.push('/recommendations')
}

function formatReads(value?: number) {
  const num = Number(value || 0)
  if (!num) return '刚刚上架'
  if (num >= 10000) {
    return `${(num / 10000).toFixed(1)} 万人在读`
  }
  return `${num} 人在读`
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

async function loadHomeData() {
  try {
    const [tagsRes, categoriesRes, rankingRes] = await Promise.all([
      getHotTags(),
      getHighlightedCategories(),
      getBookRankings({ type: 'high_score', limit: 4 }),
    ])
    tags.value = tagsRes.items || []
    categories.value = categoriesRes.items || []
    rankingBooks.value = rankingRes.items || []
  } catch (_error) {
    ElMessage.warning('首页推荐数据加载不完整，已尽量展示可用内容')
  }
  await loadHomeBooks()
}

async function selectCategory(categoryId: number | null) {
  activeCategoryId.value = categoryId
  await loadHomeBooks()
}

async function selectTag(tagId: number | null) {
  activeTagId.value = tagId
  await loadHomeBooks()
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
    <header class="sticky top-0 z-20 border-b border-stone-200 bg-white/90 backdrop-blur">
      <div class="mx-auto flex h-16 max-w-6xl items-center justify-between px-4">
        <button class="text-xl font-semibold" @click="router.push('/')">Book Recommend</button>

        <div class="flex items-center gap-3">
          <button
            class="hidden rounded-full border border-stone-300 px-4 py-2 text-sm md:inline-block"
            @click="router.push('/user/library')"
          >
            我的阅读
          </button>

          <button class="flex items-center gap-2 rounded-full p-1 pr-3 hover:bg-stone-100" @click="goProfile">
            <img
              :src="currentUser?.avatar_url || defaultAvatar"
              alt="avatar"
              class="h-9 w-9 rounded-full object-cover"
            />
            <span class="text-sm">{{ currentUser?.name || currentUser?.username || '去登录' }}</span>
          </button>
        </div>
      </div>
    </header>

    <main class="mx-auto max-w-6xl px-4 py-10">
      <section class="rounded-3xl bg-[#171717] p-8 text-white md:p-12">
        <p class="text-sm text-stone-300">本周精选</p>
        <h1 class="mt-3 text-4xl font-semibold leading-tight">下一本让你读下去的书，也许就在这里。</h1>
        <p class="mt-3 max-w-2xl text-stone-300">
          {{ heroBook ? `从《${heroBook.title}》开始，看看最近口碑最好的阅读选择。` : '按分类、标签和口碑榜单，慢慢挑到你今晚最想翻开的那一本。' }}
        </p>
        <div class="mt-6 flex flex-wrap items-center gap-3">
          <button
            class="rounded-full bg-white px-6 py-3 text-sm font-medium text-stone-900"
            @click="heroBook ? goBook(heroBook.id) : goMoreRecommendations()"
          >
            {{ heroBook ? '查看本周主推' : '开始找书' }}
          </button>
          <button
            class="rounded-full border border-white/20 px-6 py-3 text-sm font-medium text-white"
            @click="goMoreRecommendations"
          >
            浏览更多推荐
          </button>
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

        <div class="mb-4 flex items-center justify-between">
          <div>
            <h2 class="text-2xl font-semibold">为你推荐</h2>
            <p class="mt-1 text-sm text-stone-500">从最近高分、热门题材和读者反馈里，先挑 8 本更值得点开的。</p>
          </div>
          <button class="text-sm font-medium text-stone-700 hover:text-stone-900" @click="goMoreRecommendations">更多推荐 ></button>
        </div>

        <div v-if="loadingBooks" class="rounded-xl bg-white p-6 text-center text-sm text-stone-500">推荐书籍加载中...</div>

        <div v-else-if="books.length === 0" class="rounded-2xl bg-white p-8 text-center text-sm text-stone-500 shadow-sm">
          暂时没有找到匹配的书，试试切换标签或分类。
        </div>

        <div v-else class="grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
          <article
            v-for="book in books"
            :key="book.id"
            class="cursor-pointer rounded-2xl bg-white p-3 shadow-sm transition hover:-translate-y-0.5 hover:shadow-md"
            @click="goBook(book.id)"
          >
            <img :src="book.cover || ''" :alt="book.title" class="aspect-[3/4] w-full rounded-xl object-cover" />
            <h3 class="mt-3 line-clamp-1 text-sm font-semibold">{{ book.title }}</h3>
            <p class="mt-1 text-xs text-stone-500">{{ book.author || '作者待补充' }}</p>
            <p class="mt-2 text-xs text-amber-600">评分 {{ book.rating || book.score || '-' }}</p>
            <p class="mt-1 text-xs text-stone-400">{{ formatReads(book.recent_reads) }}</p>
          </article>
        </div>
      </section>

      <section class="mt-10 grid gap-5 lg:grid-cols-[minmax(0,1fr)_320px]">
        <div class="rounded-2xl bg-white p-5 shadow-sm">
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
          <p class="text-sm text-stone-500">按题材缩小范围，更快找到你现在想读的那一类书。</p>
        </div>

        <aside class="rounded-2xl bg-white p-5 shadow-sm">
          <h3 class="text-lg font-semibold">高分口碑榜</h3>
          <div class="mt-4 space-y-3">
            <article
              v-for="item in rankingBooks"
              :key="`rank-${item.id}`"
              class="flex cursor-pointer items-center gap-3 rounded-xl p-2 transition hover:bg-stone-50"
              @click="goBook(item.id)"
            >
              <div class="w-7 text-sm font-semibold text-amber-600">{{ item.rank }}</div>
              <img :src="item.cover || ''" :alt="item.title" class="h-14 w-10 rounded object-cover" />
              <div class="min-w-0">
                <p class="truncate text-sm font-medium">{{ item.title }}</p>
                <p class="truncate text-xs text-stone-500">{{ item.author || '作者待补充' }}</p>
              </div>
            </article>
          </div>
        </aside>
      </section>
    </main>
  </div>
</template>
