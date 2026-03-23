<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { getToken } from '@/api/request'
import { getUserProfile, type UserProfile } from '@/api/user'

const router = useRouter()

const currentUser = ref<UserProfile | null>(null)
const defaultAvatar =
  'https://images.unsplash.com/photo-1438761681033-6461ffad8d80?auto=format&fit=crop&w=200&q=80'

const books = [
  {
    id: 1,
    title: '漫长的余生',
    author: '罗新',
    rating: 9.4,
    cover:
      'https://images.unsplash.com/photo-1512820790803-83ca734da794?auto=format&fit=crop&w=900&q=80',
  },
  {
    id: 2,
    title: '夜晚的潜水艇',
    author: '陈春成',
    rating: 9.1,
    cover:
      'https://images.unsplash.com/photo-1481627834876-b7833e8f5570?auto=format&fit=crop&w=900&q=80',
  },
  {
    id: 3,
    title: '克拉拉与太阳',
    author: '石黑一雄',
    rating: 9.0,
    cover:
      'https://images.unsplash.com/photo-1495446815901-a7297e633e8d?auto=format&fit=crop&w=900&q=80',
  },
  {
    id: 4,
    title: '置身事内',
    author: '兰小欢',
    rating: 8.8,
    cover:
      'https://images.unsplash.com/photo-1474932430478-367dbb6832c1?auto=format&fit=crop&w=900&q=80',
  },
]

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

async function loadProfile() {
  if (!getToken()) return
  try {
    const res = await getUserProfile()
    currentUser.value = res.user
  } catch {
    currentUser.value = null
  }
}

onMounted(loadProfile)
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
        <p class="text-sm text-stone-300">本周推荐</p>
        <h1 class="mt-3 text-4xl font-semibold leading-tight">在阅读中发现下一本好书</h1>
        <p class="mt-3 max-w-2xl text-stone-300">首页书籍卡片现在支持点击跳转到图书详情页。</p>
        <button class="mt-6 rounded-full bg-white px-6 py-3 text-sm font-medium text-stone-900" @click="goBook(1)">
          开始阅读
        </button>
      </section>

      <section class="mt-10">
        <div class="mb-4 flex items-center justify-between">
          <h2 class="text-2xl font-semibold">为你推荐</h2>
        </div>

        <div class="grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
          <article
            v-for="book in books"
            :key="`${book.title}-${book.author}`"
            class="cursor-pointer rounded-2xl bg-white p-3 shadow-sm transition hover:-translate-y-0.5 hover:shadow-md"
            @click="goBook(book.id)"
          >
            <img :src="book.cover" :alt="book.title" class="aspect-[3/4] w-full rounded-xl object-cover" />
            <h3 class="mt-3 line-clamp-1 text-sm font-semibold">{{ book.title }}</h3>
            <p class="mt-1 text-xs text-stone-500">{{ book.author }}</p>
            <p class="mt-2 text-xs text-amber-600">评分 {{ book.rating }}</p>
          </article>
        </div>
      </section>
    </main>
  </div>
</template>
