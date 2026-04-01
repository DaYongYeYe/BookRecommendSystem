<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { useRouter } from 'vue-router'
import { getCreatorBookAnalytics, getCreatorBooks, type CreatorBookAnalyticsItem, type CreatorBookItem } from '@/api/creator'
import { getUserProfile, updateUserProfile, uploadUserAvatar, type UserProfile } from '@/api/user'
import { isCreatorToken } from '@/utils/auth'

const router = useRouter()
const loading = ref(false)
const saving = ref(false)
const uploadingAvatar = ref(false)
const profile = ref<UserProfile | null>(null)
const creatorBooks = ref<CreatorBookItem[]>([])
const creatorAnalytics = ref<CreatorBookAnalyticsItem[]>([])
const creatorSummaryLoading = ref(false)

const form = reactive({
  name: '',
  pen_name: '',
  avatar_url: '',
  age: null as number | null,
  province: '',
  city: '',
})

const defaultAvatar =
  'https://images.unsplash.com/photo-1438761681033-6461ffad8d80?auto=format&fit=crop&w=240&q=80'

const canOpenCreator = computed(() => isCreatorToken())
const publishedBooks = computed(() => creatorBooks.value.filter((item) => item.status === 'published'))
const creatorFeedbackSummary = computed(() =>
  creatorAnalytics.value.reduce(
    (acc, item) => {
      acc.reads += item.metrics.reads
      acc.readUsers += item.metrics.read_users
      acc.impressions += item.metrics.impressions
      return acc
    },
    { impressions: 0, reads: 0, readUsers: 0 }
  )
)
const recentCreatorBooks = computed(() => creatorBooks.value.slice(0, 3))

async function loadProfile() {
  loading.value = true
  try {
    const res = await getUserProfile()
    profile.value = res.user
    form.name = res.user.name || ''
    form.pen_name = res.user.pen_name || ''
    form.avatar_url = res.user.avatar_url || ''
    form.age = typeof res.user.age === 'number' ? res.user.age : null
    form.province = res.user.province || ''
    form.city = res.user.city || ''
  } catch (_error) {
    ElMessage.error('用户信息加载失败')
  } finally {
    loading.value = false
  }
}

async function loadCreatorSummary() {
  if (!canOpenCreator.value) {
    creatorBooks.value = []
    creatorAnalytics.value = []
    return
  }

  creatorSummaryLoading.value = true
  try {
    const [booksRes, analyticsRes] = await Promise.all([getCreatorBooks(), getCreatorBookAnalytics({ limit: 20 })])
    creatorBooks.value = booksRes.items || []
    creatorAnalytics.value = analyticsRes.items || []
  } catch {
    creatorBooks.value = []
    creatorAnalytics.value = []
  } finally {
    creatorSummaryLoading.value = false
  }
}

async function saveProfile() {
  if (!profile.value) return
  saving.value = true
  try {
    const res = await updateUserProfile({
      name: form.name,
      pen_name: form.pen_name,
      avatar_url: form.avatar_url,
      age: form.age,
      province: form.province,
      city: form.city,
    })
    profile.value = res.user
    form.pen_name = res.user.pen_name || ''
    form.age = typeof res.user.age === 'number' ? res.user.age : null
    ElMessage.success('资料保存成功')
  } catch (_error: any) {
    ElMessage.error(_error?.response?.data?.error || '资料保存失败')
  } finally {
    saving.value = false
  }
}

async function handleAvatarChange(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return

  uploadingAvatar.value = true
  try {
    const res = await uploadUserAvatar(file)
    form.avatar_url = res.avatar_url || ''
    profile.value = res.user
    ElMessage.success('头像上传成功')
  } catch (_error: any) {
    ElMessage.error(_error?.response?.data?.error || '头像上传失败')
  } finally {
    uploadingAvatar.value = false
    input.value = ''
  }
}

onMounted(async () => {
  await loadProfile()
  await loadCreatorSummary()
})
</script>

<template>
  <div class="min-h-screen bg-stone-100 px-4 py-10 text-stone-900">
    <div class="mx-auto max-w-5xl">
      <div class="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div class="flex items-center gap-2">
          <button class="rounded-full border border-stone-300 px-4 py-2 text-sm" @click="router.push('/')">返回首页</button>
          <button
            class="rounded-full border border-emerald-300 bg-emerald-50 px-4 py-2 text-sm text-emerald-700"
            @click="router.push('/creator-center')"
          >
            {{ canOpenCreator ? '进入创作中心' : '作者入口' }}
          </button>
        </div>
        <button class="rounded-full bg-stone-900 px-4 py-2 text-sm text-white" @click="router.push('/user/library')">
          我的阅读
        </button>
      </div>

      <div class="grid gap-5 lg:grid-cols-[minmax(0,1.2fr)_minmax(280px,0.8fr)]">
        <section class="rounded-3xl bg-white p-6 shadow-sm md:p-8">
          <div class="flex items-start justify-between gap-4">
            <div>
              <h1 class="text-2xl font-semibold">账号资料</h1>
              <p class="mt-2 text-sm text-stone-500">这里保留账户、头像、笔名和地区等共享信息，创作后台则放到独立创作中心里。</p>
            </div>
            <span
              class="rounded-full px-3 py-1 text-xs font-medium"
              :class="canOpenCreator ? 'bg-emerald-50 text-emerald-700' : 'bg-stone-100 text-stone-600'"
            >
              {{ canOpenCreator ? '创作者身份已开通' : '当前为阅读端身份' }}
            </span>
          </div>

          <div v-if="loading" class="mt-8 text-sm text-stone-500">正在加载...</div>

          <template v-else-if="profile">
            <div class="mt-8 grid gap-8 md:grid-cols-[220px_minmax(0,1fr)]">
              <div class="flex flex-col items-center rounded-3xl bg-stone-50 p-5">
                <img
                  :src="form.avatar_url || profile.avatar_url || defaultAvatar"
                  alt="avatar"
                  class="h-32 w-32 rounded-full object-cover"
                />
                <p class="mt-3 text-sm text-stone-500">用户名：{{ profile.username }}</p>
                <p class="mt-1 text-sm text-stone-500">年龄：{{ profile.age ?? '未填写' }}</p>
                <p class="mt-1 text-sm text-stone-500">当前笔名：{{ profile.pen_name || '未设置' }}</p>
              </div>

              <div class="space-y-5">
                <label class="block">
                  <span class="mb-2 block text-sm text-stone-600">名称</span>
                  <input
                    v-model="form.name"
                    class="w-full rounded-2xl border border-stone-200 px-4 py-3 outline-none focus:border-stone-500"
                    placeholder="请输入名称"
                  />
                </label>

                <label class="block">
                  <span class="mb-2 block text-sm text-stone-600">创作者笔名</span>
                  <input
                    v-model="form.pen_name"
                    class="w-full rounded-2xl border border-stone-200 px-4 py-3 outline-none focus:border-stone-500"
                    maxlength="80"
                    placeholder="进入创作中心前建议先设置笔名"
                  />
                  <p class="mt-2 text-xs text-stone-500">
                    笔名属于共享资料，会展示在公开作品中；真正的草稿、章节和分析数据则只放在创作中心。
                  </p>
                </label>

                <label class="block">
                  <span class="mb-2 block text-sm text-stone-600">年龄</span>
                  <input
                    v-model.number="form.age"
                    type="number"
                    min="1"
                    max="120"
                    class="w-full rounded-2xl border border-stone-200 px-4 py-3 outline-none focus:border-stone-500"
                    placeholder="请输入年龄（1-120）"
                  />
                </label>

                <div class="grid grid-cols-1 gap-4 md:grid-cols-2">
                  <label class="block">
                    <span class="mb-2 block text-sm text-stone-600">省份</span>
                    <input
                      v-model="form.province"
                      class="w-full rounded-2xl border border-stone-200 px-4 py-3 outline-none focus:border-stone-500"
                      placeholder="可手动修改"
                    />
                  </label>
                  <label class="block">
                    <span class="mb-2 block text-sm text-stone-600">城市</span>
                    <input
                      v-model="form.city"
                      class="w-full rounded-2xl border border-stone-200 px-4 py-3 outline-none focus:border-stone-500"
                      placeholder="可手动修改"
                    />
                  </label>
                </div>

                <label class="block">
                  <span class="mb-2 block text-sm text-stone-600">上传头像</span>
                  <input
                    type="file"
                    accept="image/png,image/jpeg,image/webp"
                    class="block w-full text-sm text-stone-600 file:mr-4 file:rounded-full file:border-0 file:bg-stone-900 file:px-4 file:py-2 file:text-sm file:text-white"
                    :disabled="uploadingAvatar"
                    @change="handleAvatarChange"
                  />
                  <p class="mt-2 text-xs text-stone-500">支持 JPG、PNG、WEBP，最大 2MB</p>
                </label>

                <p class="text-sm text-stone-500">邮箱：{{ profile.email }}</p>

                <button
                  class="rounded-full bg-stone-900 px-6 py-3 text-sm font-medium text-white disabled:opacity-60"
                  :disabled="saving"
                  @click="saveProfile"
                >
                  {{ saving ? '保存中...' : '保存资料' }}
                </button>
              </div>
            </div>
          </template>
        </section>

        <aside class="space-y-5">
          <section class="rounded-3xl bg-white p-6 shadow-sm">
            <p class="text-sm text-stone-500">作者身份</p>
            <h2 class="mt-1 text-xl font-semibold">共享给阅读端的创作者信息</h2>

            <div class="mt-5 space-y-4 text-sm text-stone-600">
              <div class="rounded-2xl bg-stone-50 p-4">
                <p class="font-medium text-stone-900">账号资料</p>
                <p class="mt-2">头像、昵称、笔名、地区等基础资料继续统一管理。</p>
              </div>
              <div class="rounded-2xl bg-stone-50 p-4">
                <p class="font-medium text-stone-900">作品与反馈摘要</p>
                <p class="mt-2">只保留公开作品概览和读者反馈摘要，不把草稿、审核与运营工具暴露到阅读端。</p>
              </div>
              <div class="rounded-2xl bg-stone-50 p-4">
                <p class="font-medium text-stone-900">创作中心入口</p>
                <p class="mt-2">需要处理写作、章节、分析时，再进入独立创作中心完成。</p>
              </div>
            </div>

            <button
              class="mt-5 w-full rounded-full border border-emerald-300 bg-emerald-50 px-4 py-3 text-sm text-emerald-700"
              @click="router.push('/creator-center')"
            >
              {{ canOpenCreator ? '打开创作中心入口' : '查看如何成为作者' }}
            </button>
          </section>

          <section class="rounded-3xl bg-white p-6 shadow-sm">
            <div class="flex items-center justify-between gap-3">
              <div>
                <p class="text-sm text-stone-500">读者反馈数据摘要</p>
                <h2 class="mt-1 text-xl font-semibold">创作者概览</h2>
              </div>
              <span v-if="creatorSummaryLoading" class="text-xs text-stone-400">加载中...</span>
            </div>

            <template v-if="canOpenCreator">
              <div class="mt-5 grid grid-cols-2 gap-3">
                <div class="rounded-2xl bg-stone-50 p-4">
                  <p class="text-xs text-stone-500">公开作品</p>
                  <p class="mt-2 text-2xl font-semibold text-stone-900">{{ publishedBooks.length }}</p>
                </div>
                <div class="rounded-2xl bg-stone-50 p-4">
                  <p class="text-xs text-stone-500">累计阅读</p>
                  <p class="mt-2 text-2xl font-semibold text-stone-900">{{ creatorFeedbackSummary.reads }}</p>
                </div>
                <div class="rounded-2xl bg-stone-50 p-4">
                  <p class="text-xs text-stone-500">阅读用户</p>
                  <p class="mt-2 text-2xl font-semibold text-stone-900">{{ creatorFeedbackSummary.readUsers }}</p>
                </div>
                <div class="rounded-2xl bg-stone-50 p-4">
                  <p class="text-xs text-stone-500">作品曝光</p>
                  <p class="mt-2 text-2xl font-semibold text-stone-900">{{ creatorFeedbackSummary.impressions }}</p>
                </div>
              </div>

              <div class="mt-5 rounded-2xl bg-stone-50 p-4">
                <p class="text-sm font-medium text-stone-900">近期作品</p>
                <div v-if="recentCreatorBooks.length" class="mt-3 space-y-2">
                  <div
                    v-for="book in recentCreatorBooks"
                    :key="book.id"
                    class="flex items-center justify-between rounded-2xl bg-white px-4 py-3 text-sm text-stone-700"
                  >
                    <span class="truncate pr-3">{{ book.title }}</span>
                    <span class="text-xs text-stone-400">{{ book.status }}</span>
                  </div>
                </div>
                <p v-else class="mt-3 text-sm text-stone-500">还没有创作数据，进入创作中心后可以开始管理稿件。</p>
              </div>
            </template>

            <template v-else>
              <div class="mt-5 rounded-2xl bg-stone-50 p-4 text-sm leading-7 text-stone-600">
                当前页面仍然保留作者相关的共享资料位，但草稿、审核、收益、创作分析等后台内容不会出现在这里。
              </div>
            </template>
          </section>
        </aside>
      </div>
    </div>
  </div>
</template>
