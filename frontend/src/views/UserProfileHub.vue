<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { getToken } from '@/api/request'
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

function goCreatorCenter() {
  router.push('/creator-center')
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

        <div class="mt-6 grid gap-4 md:grid-cols-3">
          <button class="rounded-2xl border border-stone-200 bg-stone-50 p-5 text-left hover:border-stone-300" @click="goAccountProfile">
            <p class="text-base font-semibold">基本资料</p>
            <p class="mt-2 text-sm text-stone-500">头像、名称、笔名、地区、年龄</p>
          </button>
          <button class="rounded-2xl border border-stone-200 bg-stone-50 p-5 text-left hover:border-stone-300" @click="goLibrary">
            <p class="text-base font-semibold">我的阅读</p>
            <p class="mt-2 text-sm text-stone-500">收藏、阅读进度与历史记录</p>
          </button>
          <button class="rounded-2xl border border-stone-200 bg-stone-50 p-5 text-left hover:border-stone-300" @click="goCreatorCenter">
            <p class="text-base font-semibold">创作者信息</p>
            <p class="mt-2 text-sm text-stone-500">申请创作者并进入创作中心</p>
          </button>
        </div>
      </section>
    </div>
  </div>
</template>
