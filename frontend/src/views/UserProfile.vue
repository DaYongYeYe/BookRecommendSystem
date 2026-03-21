<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { useRouter } from 'vue-router'
import { getUserProfile, updateUserProfile, type UserProfile } from '@/api/user'

const router = useRouter()
const loading = ref(false)
const saving = ref(false)
const profile = ref<UserProfile | null>(null)

const form = reactive({
  name: '',
  avatar_url: '',
})

const defaultAvatar =
  'https://images.unsplash.com/photo-1438761681033-6461ffad8d80?auto=format&fit=crop&w=240&q=80'

async function loadProfile() {
  loading.value = true
  try {
    const res = await getUserProfile()
    profile.value = res.user
    form.name = res.user.name || ''
    form.avatar_url = res.user.avatar_url || ''
  } catch (_error) {
    ElMessage.error('用户信息加载失败')
  } finally {
    loading.value = false
  }
}

async function saveProfile() {
  if (!profile.value) return
  saving.value = true
  try {
    const res = await updateUserProfile({
      name: form.name,
      avatar_url: form.avatar_url,
    })
    profile.value = res.user
    ElMessage.success('资料保存成功')
  } catch (_error: any) {
    ElMessage.error(_error?.response?.data?.error || '资料保存失败')
  } finally {
    saving.value = false
  }
}

onMounted(loadProfile)
</script>

<template>
  <div class="min-h-screen bg-stone-100 px-4 py-10 text-stone-900">
    <div class="mx-auto max-w-4xl">
      <div class="mb-4 flex items-center justify-between">
        <button class="rounded-full border border-stone-300 px-4 py-2 text-sm" @click="router.push('/')">返回首页</button>
        <button class="rounded-full bg-stone-900 px-4 py-2 text-sm text-white" @click="router.push('/user/library')">
          我的阅读
        </button>
      </div>

      <div class="rounded-3xl bg-white p-6 shadow-sm md:p-8">
        <h1 class="text-2xl font-semibold">用户详情</h1>
        <p class="mt-2 text-sm text-stone-500">可在这里设置头像和名称</p>

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
                <span class="mb-2 block text-sm text-stone-600">头像链接</span>
                <input
                  v-model="form.avatar_url"
                  class="w-full rounded-2xl border border-stone-200 px-4 py-3 outline-none focus:border-stone-500"
                  placeholder="请输入头像 URL"
                />
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
      </div>
    </div>
  </div>
</template>
