<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { getUserFavorites, getUserHistory, type BookItem } from '@/api/user'

const router = useRouter()
const loading = ref(false)
const favorites = ref<BookItem[]>([])
const history = ref<BookItem[]>([])

function goBook(bookId: number) {
  router.push(`/books/${bookId}`)
}

async function loadData() {
  loading.value = true
  try {
    const [favRes, historyRes] = await Promise.all([getUserFavorites(), getUserHistory()])
    favorites.value = favRes.items
    history.value = historyRes.items
  } catch (_error) {
    ElMessage.error('阅读数据加载失败')
  } finally {
    loading.value = false
  }
}

onMounted(loadData)
</script>

<template>
  <div class="min-h-screen bg-stone-100 px-4 py-10 text-stone-900">
    <div class="mx-auto max-w-6xl">
      <div class="mb-6 flex items-center justify-between">
        <button class="rounded-full border border-stone-300 px-4 py-2 text-sm" @click="router.push('/user/profile')">
          返回用户详情
        </button>
        <button class="rounded-full bg-stone-900 px-4 py-2 text-sm text-white" @click="router.push('/')">返回首页</button>
      </div>

      <h1 class="text-3xl font-semibold">我的阅读</h1>
      <p class="mt-2 text-sm text-stone-500">查看收藏书本与浏览记录</p>

      <div v-if="loading" class="mt-8 rounded-3xl bg-white p-8 text-sm text-stone-500 shadow-sm">正在加载...</div>

      <div v-else class="mt-8 grid gap-6 lg:grid-cols-2">
        <section class="rounded-3xl bg-white p-6 shadow-sm">
          <h2 class="text-xl font-semibold">我的收藏 ({{ favorites.length }})</h2>
          <div v-if="favorites.length === 0" class="mt-4 text-sm text-stone-500">暂无收藏</div>
          <div v-else class="mt-4 space-y-4">
            <div
              v-for="item in favorites"
              :key="`fav-${item.id}`"
              class="flex cursor-pointer items-center gap-4 rounded-2xl border border-stone-100 p-3"
              @click="goBook(item.id)"
            >
              <img :src="item.cover" :alt="item.title" class="h-20 w-14 rounded object-cover" />
              <div class="min-w-0 flex-1">
                <h3 class="truncate text-sm font-semibold">{{ item.title }}</h3>
                <p class="mt-1 truncate text-xs text-stone-500">{{ item.author || '未知作者' }}</p>
              </div>
            </div>
          </div>
        </section>

        <section class="rounded-3xl bg-white p-6 shadow-sm">
          <h2 class="text-xl font-semibold">浏览记录 ({{ history.length }})</h2>
          <div v-if="history.length === 0" class="mt-4 text-sm text-stone-500">暂无浏览记录</div>
          <div v-else class="mt-4 space-y-4">
            <div
              v-for="item in history"
              :key="`his-${item.id}`"
              class="flex cursor-pointer items-center gap-4 rounded-2xl border border-stone-100 p-3"
              @click="goBook(item.id)"
            >
              <img :src="item.cover" :alt="item.title" class="h-20 w-14 rounded object-cover" />
              <div class="min-w-0 flex-1">
                <h3 class="truncate text-sm font-semibold">{{ item.title }}</h3>
                <p class="mt-1 text-xs text-stone-500">进度：{{ Math.round(item.history?.scroll_percent || 0) }}%</p>
                <p class="mt-1 truncate text-xs text-stone-400">
                  最近阅读章节：{{ item.history?.section_id || '未记录' }}
                </p>
              </div>
            </div>
          </div>
        </section>
      </div>
    </div>
  </div>
</template>
