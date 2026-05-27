<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { getReadingStats, type ReadingStatsPayload } from '@/api/user'
import { USER_PROFILE_HUB_ROUTE_NAME } from '@/constants/routes'

const router = useRouter()
const loading = ref(false)
const payload = ref<ReadingStatsPayload | null>(null)

const stats = computed(() => payload.value?.stats)
const preferences = computed(() => payload.value?.preferences)
const unlockedCount = computed(() => payload.value?.achievements.filter((item) => item.unlocked).length || 0)

const themeLabelMap: Record<string, string> = {
  light: '浅色',
  dark: '深色',
  green: '护眼绿',
  parchment: '羊皮纸',
}

const marginLabelMap: Record<string, string> = {
  narrow: '窄版',
  medium: '标准',
  wide: '宽版',
}

function formatMinutes(minutes?: number) {
  const value = Number(minutes || 0)
  if (value < 60) return `${value} 分钟`
  const hours = Math.floor(value / 60)
  const rest = value % 60
  return rest ? `${hours} 小时 ${rest} 分钟` : `${hours} 小时`
}

function formatDate(value?: string | null) {
  if (!value) return '尚未解锁'
  return value.slice(0, 10)
}

function goBook(bookId: number) {
  router.push(`/books/${bookId}`)
}

async function loadData() {
  loading.value = true
  try {
    payload.value = await getReadingStats()
  } catch (_error) {
    ElMessage.error('阅读统计加载失败，请稍后重试')
  } finally {
    loading.value = false
  }
}

onMounted(loadData)
</script>

<template>
  <div class="min-h-screen bg-[linear-gradient(180deg,#f5f1e8_0%,#f7f7f5_32%,#ffffff_100%)] px-4 py-10 text-stone-900">
    <main class="mx-auto max-w-6xl">
      <div class="mb-6 flex flex-wrap items-center justify-between gap-3">
        <button
          class="rounded-full border border-stone-300 bg-white px-4 py-2 text-sm text-stone-700 transition hover:border-stone-500"
          @click="router.push({ name: USER_PROFILE_HUB_ROUTE_NAME })"
        >
          返回个人中心
        </button>
        <button class="rounded-full bg-stone-900 px-4 py-2 text-sm text-white" @click="router.push('/user/library')">
          我的阅读
        </button>
      </div>

      <section class="overflow-hidden rounded-[2rem] bg-[#16231f] p-6 text-white shadow-lg shadow-stone-200/70 md:p-8">
        <div class="grid gap-6 lg:grid-cols-[minmax(0,1fr)_320px]">
          <div>
            <p class="text-xs uppercase tracking-[0.32em] text-stone-300">Reading Stats</p>
            <h1 class="mt-3 text-4xl font-semibold leading-tight">阅读数据与偏好同步</h1>
            <p class="mt-4 max-w-2xl text-sm leading-7 text-stone-300">
              汇总本周阅读时长、阅读天数、书架、划线、评论、书签和轻量成就。阅读器里修改主题、字号和页面宽度后，这里会读取同一份后端偏好数据。
            </p>
          </div>
          <div class="rounded-[1.5rem] bg-white/10 p-5">
            <p class="text-sm text-stone-300">本周开始</p>
            <p class="mt-2 text-2xl font-semibold">{{ payload?.week_start || '--' }}</p>
            <div class="mt-5 grid grid-cols-2 gap-3">
              <div class="rounded-2xl bg-white/10 p-4">
                <p class="text-xs text-stone-300">连续阅读</p>
                <p class="mt-2 text-2xl font-semibold">{{ stats?.reading_streak_days || 0 }} 天</p>
              </div>
              <div class="rounded-2xl bg-white/10 p-4">
                <p class="text-xs text-stone-300">已解锁</p>
                <p class="mt-2 text-2xl font-semibold">{{ unlockedCount }} 枚</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section v-if="loading" class="mt-8 rounded-[2rem] bg-white p-10 text-center text-sm text-stone-500 shadow-sm">
        正在加载阅读统计...
      </section>

      <template v-else-if="payload && stats && preferences">
        <section class="mt-8 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <div class="rounded-[1.5rem] bg-white p-5 shadow-sm">
            <p class="text-sm text-stone-500">本周阅读时长</p>
            <p class="mt-3 text-3xl font-semibold">{{ formatMinutes(stats.weekly_read_minutes) }}</p>
          </div>
          <div class="rounded-[1.5rem] bg-white p-5 shadow-sm">
            <p class="text-sm text-stone-500">本周阅读天数</p>
            <p class="mt-3 text-3xl font-semibold">{{ stats.weekly_reading_days }} 天</p>
          </div>
          <div class="rounded-[1.5rem] bg-white p-5 shadow-sm">
            <p class="text-sm text-stone-500">完成章节</p>
            <p class="mt-3 text-3xl font-semibold">{{ stats.completed_chapter_count }} 章</p>
          </div>
          <div class="rounded-[1.5rem] bg-white p-5 shadow-sm">
            <p class="text-sm text-stone-500">书架收藏</p>
            <p class="mt-3 text-3xl font-semibold">{{ stats.shelf_count }} 本</p>
          </div>
          <div class="rounded-[1.5rem] bg-white p-5 shadow-sm">
            <p class="text-sm text-stone-500">划线笔记</p>
            <p class="mt-3 text-3xl font-semibold">{{ stats.highlight_count }} 条</p>
          </div>
          <div class="rounded-[1.5rem] bg-white p-5 shadow-sm">
            <p class="text-sm text-stone-500">评论讨论</p>
            <p class="mt-3 text-3xl font-semibold">{{ stats.comment_count }} 条</p>
          </div>
          <div class="rounded-[1.5rem] bg-white p-5 shadow-sm">
            <p class="text-sm text-stone-500">书签</p>
            <p class="mt-3 text-3xl font-semibold">{{ stats.bookmark_count }} 个</p>
          </div>
          <div class="rounded-[1.5rem] bg-white p-5 shadow-sm">
            <p class="text-sm text-stone-500">偏好更新时间</p>
            <p class="mt-3 text-base font-semibold">{{ preferences.updated_at?.slice(0, 16).replace('T', ' ') || '默认偏好' }}</p>
          </div>
        </section>

        <section class="mt-8 grid gap-6 lg:grid-cols-[minmax(0,1fr)_360px]">
          <section class="rounded-[2rem] bg-white p-6 shadow-sm md:p-8">
            <div class="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 class="text-2xl font-semibold">阅读成就</h2>
                <p class="mt-1 text-sm text-stone-500">基于书架、划线、章节进度和本周阅读时长自动解锁。</p>
              </div>
              <span class="rounded-full bg-stone-100 px-4 py-2 text-xs text-stone-600">{{ unlockedCount }} / {{ payload.achievements.length }}</span>
            </div>

            <div class="mt-6 grid gap-4 md:grid-cols-2">
              <article
                v-for="item in payload.achievements"
                :key="item.achievement_key"
                class="rounded-[1.4rem] border p-5"
                :class="item.unlocked ? 'border-emerald-200 bg-emerald-50' : 'border-stone-200 bg-stone-50'"
              >
                <div class="flex items-center justify-between gap-3">
                  <h3 class="text-base font-semibold">{{ item.title }}</h3>
                  <span
                    class="rounded-full px-3 py-1 text-xs"
                    :class="item.unlocked ? 'bg-emerald-600 text-white' : 'bg-white text-stone-500'"
                  >
                    {{ item.unlocked ? '已解锁' : '未解锁' }}
                  </span>
                </div>
                <p class="mt-3 text-sm leading-6 text-stone-600">{{ item.description }}</p>
                <p class="mt-4 text-xs text-stone-400">{{ formatDate(item.unlocked_at) }}</p>
              </article>
            </div>
          </section>

          <aside class="space-y-6">
            <section class="rounded-[2rem] bg-white p-6 shadow-sm">
              <h2 class="text-2xl font-semibold">当前阅读偏好</h2>
              <div class="mt-5 space-y-3 text-sm">
                <div class="flex items-center justify-between rounded-2xl bg-stone-50 px-4 py-3">
                  <span class="text-stone-500">主题</span>
                  <span class="font-medium">{{ themeLabelMap[preferences.theme] || preferences.theme }}</span>
                </div>
                <div class="flex items-center justify-between rounded-2xl bg-stone-50 px-4 py-3">
                  <span class="text-stone-500">字号</span>
                  <span class="font-medium">{{ preferences.font_size }}px</span>
                </div>
                <div class="flex items-center justify-between rounded-2xl bg-stone-50 px-4 py-3">
                  <span class="text-stone-500">行高</span>
                  <span class="font-medium">{{ preferences.line_height }}</span>
                </div>
                <div class="flex items-center justify-between rounded-2xl bg-stone-50 px-4 py-3">
                  <span class="text-stone-500">版心</span>
                  <span class="font-medium">{{ marginLabelMap[preferences.margin] || preferences.margin }}</span>
                </div>
                <div class="flex items-center justify-between rounded-2xl bg-stone-50 px-4 py-3">
                  <span class="text-stone-500">划线/讨论</span>
                  <span class="font-medium">{{ preferences.show_highlights ? '显示划线' : '隐藏划线' }} · {{ preferences.show_comments ? '显示讨论' : '隐藏讨论' }}</span>
                </div>
              </div>
            </section>

            <section class="rounded-[2rem] bg-white p-6 shadow-sm">
              <h2 class="text-2xl font-semibold">最近阅读</h2>
              <div class="mt-5 space-y-3">
                <button
                  v-for="book in payload.recent_books"
                  :key="book.id"
                  class="flex w-full items-center gap-3 rounded-2xl border border-stone-100 p-3 text-left transition hover:border-stone-300 hover:bg-stone-50"
                  @click="goBook(book.id)"
                >
                  <img :src="book.cover || ''" :alt="book.title" class="h-20 w-14 rounded-xl object-cover" />
                  <span class="min-w-0 flex-1">
                    <span class="block truncate text-sm font-semibold">{{ book.title }}</span>
                    <span class="mt-1 block text-xs text-stone-500">{{ book.author || '作者待补充' }}</span>
                    <span class="mt-2 block text-xs text-stone-400">进度 {{ Math.round(book.scroll_percent || 0) }}%</span>
                  </span>
                </button>
                <p v-if="payload.recent_books.length === 0" class="rounded-2xl bg-stone-50 p-5 text-sm text-stone-500">
                  还没有阅读进度，先从首页或榜单打开一本书。
                </p>
              </div>
            </section>
          </aside>
        </section>
      </template>
    </main>
  </div>
</template>
