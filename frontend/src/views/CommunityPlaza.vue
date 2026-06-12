<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { getToken } from '@/api/request'
import { getMoreRecommendations, type HomeBookItem } from '@/api/home'
import AppLogo from '@/components/AppLogo.vue'
import {
  addBookToCommunityBooklist,
  createCommunityBooklist,
  createCommunityReview,
  getCommunityBooklists,
  getCommunityReviews,
  getInterestTags,
  reactCommunityReview,
  type CommunityBookList,
  type CommunityReview,
  type InterestTag,
} from '@/api/community'

const router = useRouter()

const activeTab = ref<'booklists' | 'reviews'>('booklists')
const loading = ref(false)
const booklists = ref<CommunityBookList[]>([])
const reviews = ref<CommunityReview[]>([])
const interestTags = ref<InterestTag[]>([])
const candidateBooks = ref<HomeBookItem[]>([])
const selectedListId = ref<number | null>(null)
const selectedBookId = ref<number | null>(null)
const selectedReviewBookId = ref<number | null>(null)

const booklistForm = reactive({
  title: '',
  description: '',
})
const addBookForm = reactive({
  note: '',
})
const reviewForm = reactive({
  title: '',
  content: '',
  rating: 5,
})

const selectedBook = computed(() => candidateBooks.value.find((book) => book.id === selectedBookId.value) || null)
const selectedReviewBook = computed(() => candidateBooks.value.find((book) => book.id === selectedReviewBookId.value) || null)
const isLoggedIn = computed(() => Boolean(getToken()))

function guardLogin() {
  if (getToken()) return true
  router.push({ path: '/login', query: { redirect: '/community' } })
  return false
}

function goBook(bookId: number) {
  router.push(`/books/${bookId}`)
}

function pickBook(book: HomeBookItem) {
  selectedBookId.value = book.id
  if (!selectedReviewBookId.value) selectedReviewBookId.value = book.id
}

function formatDate(value?: string | null) {
  if (!value) return ''
  return value.slice(0, 10)
}

async function loadCommunity() {
  loading.value = true
  try {
    const [listsRes, reviewsRes, tagsRes, booksRes] = await Promise.all([
      getCommunityBooklists({ limit: 12 }),
      getCommunityReviews({ limit: 12 }),
      getInterestTags(10),
      getMoreRecommendations({ page: 1, page_size: 10 }),
    ])
    booklists.value = listsRes.items || []
    reviews.value = reviewsRes.items || []
    interestTags.value = tagsRes.items || []
    candidateBooks.value = booksRes.items || []
    if (!selectedListId.value && booklists.value.length) selectedListId.value = booklists.value[0].id
    if (!selectedBookId.value && candidateBooks.value.length) selectedBookId.value = candidateBooks.value[0].id
    if (!selectedReviewBookId.value && candidateBooks.value.length) selectedReviewBookId.value = candidateBooks.value[0].id
  } catch (_error) {
    ElMessage.error('社区内容加载失败，请稍后重试')
  } finally {
    loading.value = false
  }
}

async function submitBooklist() {
  if (!guardLogin()) return
  const title = booklistForm.title.trim()
  if (!title) {
    ElMessage.warning('请填写书单标题')
    return
  }
  try {
    const res = await createCommunityBooklist({
      title,
      description: booklistForm.description.trim(),
      visibility: 'public',
    })
    booklists.value = [res.item, ...booklists.value]
    selectedListId.value = res.item.id
    booklistForm.title = ''
    booklistForm.description = ''
    ElMessage.success('书单已创建')
  } catch (_error) {
    ElMessage.error('创建书单失败')
  }
}

async function submitBookToList() {
  if (!guardLogin()) return
  if (!selectedListId.value || !selectedBookId.value) {
    ElMessage.warning('请选择书单和图书')
    return
  }
  try {
    const res = await addBookToCommunityBooklist(selectedListId.value, {
      book_id: selectedBookId.value,
      note: addBookForm.note.trim(),
    })
    booklists.value = booklists.value.map((item) => (item.id === res.item.id ? res.item : item))
    addBookForm.note = ''
    ElMessage.success('已加入书单')
  } catch (_error) {
    ElMessage.error('添加图书失败，请确认只能编辑自己的书单')
  }
}

async function submitReview() {
  if (!guardLogin()) return
  if (!selectedReviewBookId.value) {
    ElMessage.warning('请选择要评价的书')
    return
  }
  if (!reviewForm.title.trim() || reviewForm.content.trim().length < 8) {
    ElMessage.warning('请填写标题和不少于 8 个字的书评')
    return
  }
  try {
    const res = await createCommunityReview({
      book_id: selectedReviewBookId.value,
      title: reviewForm.title.trim(),
      content: reviewForm.content.trim(),
      rating: reviewForm.rating,
      visibility: 'public',
    })
    reviews.value = [res.item, ...reviews.value]
    reviewForm.title = ''
    reviewForm.content = ''
    reviewForm.rating = 5
    activeTab.value = 'reviews'
    ElMessage.success('书评已发布')
  } catch (_error) {
    ElMessage.error('发布书评失败')
  }
}

async function toggleReviewLike(review: CommunityReview) {
  if (!guardLogin()) return
  try {
    const res = await reactCommunityReview(review.id, !review.liked_by_me)
    reviews.value = reviews.value.map((item) => (item.id === review.id ? res.item : item))
  } catch (_error) {
    ElMessage.error('互动保存失败')
  }
}

onMounted(loadCommunity)
</script>

<template>
  <div class="min-h-screen bg-[#f5f3ef] text-stone-900">
    <header class="sticky top-0 z-30 border-b border-stone-200 bg-white/95 backdrop-blur">
      <div class="mx-auto flex max-w-6xl items-center gap-3 px-4 py-3">
        <button class="shrink-0" aria-label="返回阿书铺子首页" @click="router.push('/')">
          <AppLogo />
        </button>
        <button class="rounded-full border border-stone-300 px-4 py-2 text-sm text-stone-700" @click="router.push('/recommendations')">更多推荐</button>
        <button class="rounded-full border border-stone-300 px-4 py-2 text-sm text-stone-700" @click="router.push('/user/library')">我的阅读</button>
        <span class="flex-1" />
        <button
          class="rounded-full bg-stone-900 px-4 py-2 text-sm font-medium text-white"
          @click="isLoggedIn ? router.push('/user/profile-hub') : router.push({ path: '/login', query: { redirect: '/community' } })"
        >
          {{ isLoggedIn ? '个人中心' : '登录后参与' }}
        </button>
      </div>
    </header>

    <main class="mx-auto max-w-6xl px-4 py-8">
      <section class="grid gap-5 lg:grid-cols-[minmax(0,1.15fr)_360px]">
        <div class="rounded-[1.75rem] bg-[#1e2a23] p-7 text-white shadow-sm md:p-9">
          <p class="text-sm text-emerald-100">社区广场</p>
          <h1 class="mt-2 max-w-3xl text-4xl font-semibold leading-tight">把一本书变成一组书单、一段书评和下一次推荐。</h1>
          <p class="mt-4 max-w-2xl text-sm leading-7 text-stone-200">这里聚合读者创建的公开书单和书评，也会根据你的阅读、书架、搜索和推荐反馈生成兴趣标签。</p>
          <div class="mt-6 flex flex-wrap gap-3">
            <button class="rounded-full bg-white px-5 py-3 text-sm font-medium text-stone-900" @click="activeTab = 'booklists'">看书单</button>
            <button class="rounded-full border border-white/30 px-5 py-3 text-sm text-white" @click="activeTab = 'reviews'">看书评</button>
          </div>
        </div>

        <aside class="rounded-[1.75rem] bg-white p-6 shadow-sm">
          <div class="flex items-center justify-between gap-3">
            <div>
              <p class="text-sm font-medium text-stone-500">兴趣标签</p>
              <h2 class="mt-1 text-2xl font-semibold">推荐画像</h2>
            </div>
            <button class="rounded-full border border-stone-300 px-3 py-1.5 text-xs text-stone-600" @click="loadCommunity">刷新</button>
          </div>
          <div v-if="interestTags.length" class="mt-5 flex flex-wrap gap-2">
            <button
              v-for="tag in interestTags"
              :key="tag.id"
              class="rounded-full border border-emerald-100 bg-emerald-50 px-3 py-2 text-left text-sm text-emerald-800"
              @click="router.push({ path: '/search', query: { q: tag.label } })"
            >
              <span class="font-medium">{{ tag.label }}</span>
              <span class="ml-2 text-xs text-emerald-600">{{ tag.weight }}</span>
            </button>
          </div>
          <p v-else class="mt-5 rounded-2xl border border-dashed border-stone-300 bg-stone-50 p-4 text-sm text-stone-500">暂无兴趣标签，先阅读、搜索或反馈几本书。</p>
          <div class="mt-5 space-y-2 text-xs leading-5 text-stone-500">
            <p v-for="tag in interestTags.slice(0, 3)" :key="`src-${tag.id}`">{{ tag.label }}：{{ tag.source_summary || '热门标签' }}</p>
          </div>
        </aside>
      </section>

      <section class="mt-8 grid gap-6 lg:grid-cols-[minmax(0,1fr)_360px]">
        <div>
          <div class="mb-4 flex flex-wrap items-center justify-between gap-3">
            <div class="flex rounded-full border border-stone-300 bg-white p-1">
              <button
                class="rounded-full px-4 py-2 text-sm"
                :class="activeTab === 'booklists' ? 'bg-stone-900 text-white' : 'text-stone-600'"
                @click="activeTab = 'booklists'"
              >
                书单广场
              </button>
              <button
                class="rounded-full px-4 py-2 text-sm"
                :class="activeTab === 'reviews' ? 'bg-stone-900 text-white' : 'text-stone-600'"
                @click="activeTab = 'reviews'"
              >
                书评广场
              </button>
            </div>
            <span v-if="loading" class="text-sm text-stone-500">加载中...</span>
          </div>

          <div v-if="activeTab === 'booklists'" class="grid gap-4 md:grid-cols-2">
            <article
              v-for="list in booklists"
              :key="list.id"
              class="rounded-[1.25rem] bg-white p-5 shadow-sm transition hover:-translate-y-0.5 hover:shadow-md"
            >
              <div class="flex gap-4">
                <div class="grid h-28 w-24 shrink-0 grid-cols-2 gap-1 overflow-hidden rounded-2xl bg-stone-100">
                  <img
                    v-for="book in list.books.slice(0, 4)"
                    :key="book.id"
                    :src="book.cover || ''"
                    :alt="book.title"
                    class="h-full w-full object-cover"
                  />
                </div>
                <div class="min-w-0">
                  <p class="text-xs text-stone-500">{{ list.user.nickname }} · {{ list.book_count }} 本书</p>
                  <h2 class="mt-2 line-clamp-2 text-lg font-semibold">{{ list.title }}</h2>
                  <p class="mt-2 line-clamp-2 text-sm leading-6 text-stone-600">{{ list.description || '这个读者还没有写书单说明。' }}</p>
                </div>
              </div>
              <div class="mt-4 space-y-2">
                <button
                  v-for="book in list.books.slice(0, 3)"
                  :key="`list-book-${list.id}-${book.id}`"
                  class="flex w-full items-center justify-between gap-3 rounded-xl border border-stone-100 px-3 py-2 text-left text-sm hover:bg-stone-50"
                  @click="goBook(book.id)"
                >
                  <span class="truncate">{{ book.title }}</span>
                  <span class="shrink-0 text-xs text-stone-500">评分 {{ book.rating || '-' }}</span>
                </button>
              </div>
            </article>
            <p v-if="!loading && !booklists.length" class="rounded-2xl bg-white p-8 text-center text-sm text-stone-500">暂无公开书单。</p>
          </div>

          <div v-else class="space-y-4">
            <article v-for="review in reviews" :key="review.id" class="rounded-[1.25rem] bg-white p-5 shadow-sm">
              <div class="flex flex-wrap items-start justify-between gap-3">
                <div class="min-w-0">
                  <p class="text-xs text-stone-500">{{ review.user.nickname }} · {{ formatDate(review.created_at) }}</p>
                  <h2 class="mt-2 text-xl font-semibold">{{ review.title }}</h2>
                  <button v-if="review.book" class="mt-1 text-sm text-emerald-700" @click="goBook(review.book.id)">《{{ review.book.title }}》</button>
                </div>
                <span class="rounded-full bg-amber-50 px-3 py-1.5 text-sm text-amber-700">{{ review.rating || '-' }} 星</span>
              </div>
              <p class="mt-4 whitespace-pre-line text-sm leading-7 text-stone-700">{{ review.content }}</p>
              <button
                class="mt-4 rounded-full border px-4 py-2 text-sm"
                :class="review.liked_by_me ? 'border-stone-900 bg-stone-900 text-white' : 'border-stone-300 text-stone-700'"
                @click="toggleReviewLike(review)"
              >
                赞同 {{ review.likes_count }}
              </button>
            </article>
            <p v-if="!loading && !reviews.length" class="rounded-2xl bg-white p-8 text-center text-sm text-stone-500">暂无公开书评。</p>
          </div>
        </div>

        <aside class="space-y-5">
          <section class="rounded-[1.5rem] bg-white p-5 shadow-sm">
            <p class="text-sm font-medium text-stone-500">创建书单</p>
            <input v-model="booklistForm.title" class="mt-4 w-full rounded-2xl border border-stone-200 px-4 py-3 text-sm outline-none focus:border-stone-500" placeholder="书单标题" />
            <textarea v-model="booklistForm.description" class="mt-3 min-h-24 w-full rounded-2xl border border-stone-200 px-4 py-3 text-sm outline-none focus:border-stone-500" placeholder="这份书单适合谁读？" />
            <button class="mt-3 w-full rounded-full bg-stone-900 px-4 py-3 text-sm font-medium text-white" @click="submitBooklist">发布公开书单</button>
          </section>

          <section class="rounded-[1.5rem] bg-white p-5 shadow-sm">
            <p class="text-sm font-medium text-stone-500">给书单加书</p>
            <select v-model="selectedListId" class="mt-4 w-full rounded-2xl border border-stone-200 px-4 py-3 text-sm outline-none">
              <option v-for="list in booklists" :key="list.id" :value="list.id">{{ list.title }}</option>
            </select>
            <div class="mt-3 grid grid-cols-2 gap-2">
              <button
                v-for="book in candidateBooks.slice(0, 6)"
                :key="book.id"
                class="rounded-2xl border p-2 text-left text-xs"
                :class="selectedBookId === book.id ? 'border-stone-900 bg-stone-50' : 'border-stone-200'"
                @click="pickBook(book)"
              >
                <img :src="book.cover || ''" :alt="book.title" class="aspect-[3/4] w-full rounded-xl object-cover" />
                <span class="mt-2 block line-clamp-1 font-medium">{{ book.title }}</span>
              </button>
            </div>
            <textarea v-model="addBookForm.note" class="mt-3 min-h-20 w-full rounded-2xl border border-stone-200 px-4 py-3 text-sm outline-none" :placeholder="selectedBook ? `给《${selectedBook.title}》写一句推荐语` : '推荐语'" />
            <button class="mt-3 w-full rounded-full border border-stone-300 px-4 py-3 text-sm text-stone-700" @click="submitBookToList">加入所选书单</button>
          </section>

          <section class="rounded-[1.5rem] bg-white p-5 shadow-sm">
            <p class="text-sm font-medium text-stone-500">发布书评</p>
            <select v-model="selectedReviewBookId" class="mt-4 w-full rounded-2xl border border-stone-200 px-4 py-3 text-sm outline-none">
              <option v-for="book in candidateBooks" :key="book.id" :value="book.id">{{ book.title }}</option>
            </select>
            <input v-model="reviewForm.title" class="mt-3 w-full rounded-2xl border border-stone-200 px-4 py-3 text-sm outline-none focus:border-stone-500" placeholder="书评标题" />
            <div class="mt-3 flex items-center gap-3">
              <span class="text-sm text-stone-500">评分</span>
              <input v-model.number="reviewForm.rating" min="1" max="5" type="range" class="flex-1" />
              <span class="w-10 text-sm font-medium text-stone-700">{{ reviewForm.rating }} 星</span>
            </div>
            <textarea v-model="reviewForm.content" class="mt-3 min-h-28 w-full rounded-2xl border border-stone-200 px-4 py-3 text-sm outline-none focus:border-stone-500" :placeholder="selectedReviewBook ? `写下你读《${selectedReviewBook.title}》后的判断` : '写下你的书评'" />
            <button class="mt-3 w-full rounded-full bg-emerald-700 px-4 py-3 text-sm font-medium text-white" @click="submitReview">发布书评</button>
          </section>
        </aside>
      </section>
    </main>
  </div>
</template>
