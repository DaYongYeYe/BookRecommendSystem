<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { useRouter } from 'vue-router'
import {
  getHighlightedCategories,
  getHotTags,
  getMoreRecommendations,
  type HomeBookItem,
  type HomeCategoryItem,
  type HomeTagItem,
} from '@/api/home'

const router = useRouter()

const categories = ref<HomeCategoryItem[]>([])
const tags = ref<HomeTagItem[]>([])
const books = ref<HomeBookItem[]>([])
const loading = ref(false)
const page = ref(1)
const pageSize = 12
const total = ref(0)
const activeCategoryId = ref<number | null>(null)
const activeTagId = ref<number | null>(null)

function goBook(bookId: number) {
  router.push(`/books/${bookId}`)
}

async function loadFilters() {
  try {
    const [categoriesRes, tagsRes] = await Promise.all([getHighlightedCategories(), getHotTags()])
    categories.value = categoriesRes.items || []
    tags.value = tagsRes.items || []
  } catch (_error) {
    ElMessage.warning('分类和标签加载失败')
  }
}

async function loadRecommendations() {
  loading.value = true
  try {
    const res = await getMoreRecommendations({
      page: page.value,
      page_size: pageSize,
      category_id: activeCategoryId.value || undefined,
      tag_id: activeTagId.value || undefined,
    })
    books.value = res.items || []
    total.value = Number(res.pagination?.total || 0)
  } finally {
    loading.value = false
  }
}

async function onChangeCategory(categoryId: number | null) {
  activeCategoryId.value = categoryId
  page.value = 1
  await loadRecommendations()
}

async function onChangeTag(tagId: number | null) {
  activeTagId.value = tagId
  page.value = 1
  await loadRecommendations()
}

async function nextPage() {
  const pageCount = Math.ceil(total.value / pageSize)
  if (page.value >= pageCount) return
  page.value += 1
  await loadRecommendations()
}

async function prevPage() {
  if (page.value <= 1) return
  page.value -= 1
  await loadRecommendations()
}

onMounted(async () => {
  await Promise.all([loadFilters(), loadRecommendations()])
})
</script>

<template>
  <div class="min-h-screen bg-stone-100 px-4 py-8 text-stone-900">
    <div class="mx-auto max-w-6xl">
      <div class="mb-6 flex items-center justify-between">
        <h1 class="text-3xl font-semibold">更多推荐</h1>
        <button class="rounded-full border border-stone-300 px-4 py-2 text-sm hover:bg-white" @click="router.push('/')">
          返回首页
        </button>
      </div>

      <section class="rounded-2xl bg-white p-5 shadow-sm">
        <div class="mb-4 flex flex-wrap gap-2">
          <button
            class="rounded-full border px-4 py-2 text-sm transition"
            :class="
              activeCategoryId === null ? 'border-stone-900 bg-stone-900 text-white' : 'border-stone-300 bg-white text-stone-700'
            "
            @click="onChangeCategory(null)"
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
            @click="onChangeCategory(item.id)"
          >
            {{ item.name }}
          </button>
        </div>

        <div class="flex flex-wrap gap-2">
          <button
            class="rounded-full border px-4 py-2 text-sm transition"
            :class="activeTagId === null ? 'border-stone-900 bg-stone-900 text-white' : 'border-stone-300 bg-white text-stone-700'"
            @click="onChangeTag(null)"
          >
            全部标签
          </button>
          <button
            v-for="tag in tags"
            :key="tag.id"
            class="rounded-full border px-4 py-2 text-sm transition"
            :class="activeTagId === tag.id ? 'border-stone-900 bg-stone-900 text-white' : 'border-stone-300 bg-white text-stone-700'"
            @click="onChangeTag(tag.id)"
          >
            {{ tag.label }}
          </button>
        </div>
      </section>

      <section class="mt-6 rounded-2xl bg-white p-5 shadow-sm">
        <div v-if="loading" class="py-12 text-center text-sm text-stone-500">推荐列表加载中...</div>
        <template v-else>
          <div class="grid gap-4 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4">
            <article
              v-for="book in books"
              :key="book.id"
              class="cursor-pointer rounded-2xl border border-stone-100 p-3 transition hover:-translate-y-0.5 hover:shadow"
              @click="goBook(book.id)"
            >
              <img :src="book.cover || ''" :alt="book.title" class="aspect-[3/4] w-full rounded-xl object-cover" />
              <h3 class="mt-3 line-clamp-1 text-sm font-semibold">{{ book.title }}</h3>
              <p class="mt-1 text-xs text-stone-500">{{ book.author }}</p>
              <p class="mt-2 text-xs text-amber-600">评分 {{ book.rating || book.score || '-' }}</p>
            </article>
          </div>

          <div class="mt-6 flex items-center justify-end gap-2">
            <button class="rounded-full border border-stone-300 px-4 py-2 text-sm disabled:opacity-50" :disabled="page <= 1" @click="prevPage">
              上一页
            </button>
            <span class="text-sm text-stone-500">第 {{ page }} 页</span>
            <button
              class="rounded-full border border-stone-300 px-4 py-2 text-sm disabled:opacity-50"
              :disabled="page * pageSize >= total"
              @click="nextPage"
            >
              下一页
            </button>
          </div>
        </template>
      </section>
    </div>
  </div>
</template>
