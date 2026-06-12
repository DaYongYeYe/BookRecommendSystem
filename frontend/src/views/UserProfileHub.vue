<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { clearToken, getToken } from '@/api/request'
import { USER_PROFILE_ROUTE_NAME } from '@/constants/routes'
import { useUserProfileStore } from '@/stores/userProfile'

const router = useRouter()
const userProfileStore = useUserProfileStore()

const currentUser = computed(() => userProfileStore.profile)
const needsCompletion = computed(() => !currentUser.value?.name || !currentUser.value?.pen_name || !currentUser.value?.avatar_url)

function goAccountProfile() {
  router.push({ name: USER_PROFILE_ROUTE_NAME })
}

function goLibrary() {
  router.push('/user/library')
}

function goReadingStats() {
  router.push('/user/reading-stats')
}

function goCreatorCenter() {
  router.push('/creator-center')
}

function clearCurrentAccount() {
  clearToken('user')
  userProfileStore.clearProfile()
}

async function logout() {
  try {
    await ElMessageBox.confirm('退出后需要重新登录才能访问个人阅读和账号资料。', '退出登录', {
      confirmButtonText: '退出登录',
      cancelButtonText: '取消',
      type: 'warning',
    })
    clearCurrentAccount()
    ElMessage.success('已退出登录')
    router.push('/')
  } catch {
    // User cancelled.
  }
}

async function switchAccount() {
  try {
    await ElMessageBox.confirm('将退出当前账号，并跳转到登录页以切换账号。', '切换账号', {
      confirmButtonText: '去登录',
      cancelButtonText: '取消',
      type: 'info',
    })
    clearCurrentAccount()
    router.push({ path: '/login', query: { redirect: '/user/profile-hub' } })
  } catch {
    // User cancelled.
  }
}

onMounted(async () => {
  if (!getToken()) {
    router.push('/login')
    return
  }
  await userProfileStore.ensureProfileLoaded()
})
</script>

<template>
  <div class="min-h-screen bg-stone-100 px-4 py-10 text-stone-900">
    <div class="mx-auto max-w-5xl">
      <div class="mb-6 flex items-center justify-between gap-3">
        <button class="rounded-full border border-stone-300 px-4 py-2 text-sm" @click="router.push('/')">返回首页</button>
        <button class="rounded-full bg-stone-900 px-4 py-2 text-sm text-white" @click="goAccountProfile">账号资料</button>
      </div>

      <section class="rounded-3xl bg-white p-6 shadow-sm md:p-8">
        <p class="text-sm uppercase tracking-[0.2em] text-stone-400">Profile Hub</p>
        <h1 class="mt-3 text-3xl font-semibold">个人中心</h1>
        <p class="mt-2 text-sm text-stone-500">点击头像后统一进入这里，后续新增资料模块只需增加卡片，不改头像点击主链路。</p>

        <div v-if="needsCompletion" class="mt-5 rounded-2xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
          你的个人信息还未完善，建议先补充头像、名称与笔名，后续创作与展示会更完整。
        </div>

        <div class="mt-6 grid gap-4 md:grid-cols-4">
          <button class="rounded-2xl border border-stone-200 bg-stone-50 p-5 text-left hover:border-stone-300" @click="goAccountProfile">
            <p class="text-base font-semibold">基本资料</p>
            <p class="mt-2 text-sm text-stone-500">头像、名称、笔名、地区、年龄</p>
          </button>
          <button class="rounded-2xl border border-stone-200 bg-stone-50 p-5 text-left hover:border-stone-300" @click="goLibrary">
            <p class="text-base font-semibold">我的阅读</p>
            <p class="mt-2 text-sm text-stone-500">收藏、阅读进度与历史记录</p>
          </button>
          <button class="rounded-2xl border border-emerald-200 bg-emerald-50 p-5 text-left hover:border-emerald-300" @click="goReadingStats">
            <p class="text-base font-semibold text-emerald-900">阅读统计</p>
            <p class="mt-2 text-sm text-emerald-700">本周数据、阅读偏好与成就</p>
          </button>
          <button class="rounded-2xl border border-stone-200 bg-stone-50 p-5 text-left hover:border-stone-300" @click="goCreatorCenter">
            <p class="text-base font-semibold">创作者信息</p>
            <p class="mt-2 text-sm text-stone-500">申请创作者并进入创作中心</p>
          </button>
        </div>

        <div class="mt-6 rounded-2xl border border-stone-200 bg-stone-50 p-5">
          <div class="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
            <div>
              <p class="text-base font-semibold">账号选项</p>
              <p class="mt-1 text-sm text-stone-500">退出当前登录状态，或切换到另一个账号继续使用。</p>
            </div>
            <div class="flex flex-wrap gap-3">
              <button class="rounded-full border border-stone-300 bg-white px-4 py-2 text-sm text-stone-700 hover:border-stone-500" @click="switchAccount">
                切换账号
              </button>
              <button class="rounded-full border border-red-200 bg-red-50 px-4 py-2 text-sm text-red-700 hover:border-red-300 hover:bg-red-100" @click="logout">
                退出登录
              </button>
            </div>
          </div>
        </div>
      </section>
    </div>
  </div>
</template>
