<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { getToken } from '@/api/request'
import { getUserProfile, type UserProfile } from '@/api/user'
import { isCreatorToken } from '@/utils/auth'

const router = useRouter()
const profile = ref<UserProfile | null>(null)
const loading = ref(false)

const hasLogin = computed(() => Boolean(getToken()))
const canOpenCreator = computed(() => isCreatorToken())

const primaryActionLabel = computed(() => {
  if (canOpenCreator.value) return '进入创作中心'
  if (hasLogin.value) return '完善作者资料'
  return '登录后继续'
})

const secondaryHint = computed(() => {
  if (canOpenCreator.value) {
    return '你已经具备创作者身份，创作后台会以独立导航承载稿件、章节和创作数据。'
  }
  if (hasLogin.value) {
    return '当前账号以阅读身份为主。先补充笔名、头像等作者资料，再由平台开通创作者权限。'
  }
  return '先登录账号，再进入作者准备流程。'
})

async function loadProfile() {
  if (!hasLogin.value) return
  loading.value = true
  try {
    const res = await getUserProfile()
    profile.value = res.user
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载用户资料失败')
  } finally {
    loading.value = false
  }
}

function handlePrimaryAction() {
  if (canOpenCreator.value) {
    router.push('/creator/dashboard')
    return
  }

  if (!hasLogin.value) {
    router.push({
      path: '/login',
      query: { redirect: '/creator-center' },
    })
    return
  }

  router.push('/user/profile')
}

onMounted(loadProfile)
</script>

<template>
  <div class="min-h-screen bg-[linear-gradient(180deg,#f5f5f4_0%,#ecfccb_100%)] px-4 py-10 text-stone-900">
    <div class="mx-auto max-w-6xl">
      <div class="mb-6 flex flex-wrap items-center justify-between gap-3">
        <button class="rounded-full border border-stone-300 bg-white px-4 py-2 text-sm" @click="router.push('/')">
          返回阅读端
        </button>
        <button class="rounded-full border border-stone-300 bg-white px-4 py-2 text-sm" @click="router.push('/user/profile')">
          账号资料
        </button>
      </div>

      <section class="rounded-[32px] bg-stone-950 p-8 text-white shadow-xl md:p-12">
        <p class="text-sm uppercase tracking-[0.24em] text-lime-300">Creator Entry</p>
        <h1 class="mt-4 max-w-3xl text-4xl font-semibold leading-tight">阅读端继续专注读书，创作中心单独承接写作、章节与后台管理。</h1>
        <p class="mt-4 max-w-2xl text-sm leading-7 text-stone-300">
          这里是独立创作入口，不再把写作、章节管理、审核状态或创作分析直接塞进阅读首页一级导航。读者心智和作者心智分开，路径会更清楚。
        </p>

        <div class="mt-8 flex flex-wrap gap-3">
          <button class="rounded-full bg-lime-300 px-6 py-3 text-sm font-medium text-stone-950" @click="handlePrimaryAction">
            {{ primaryActionLabel }}
          </button>
          <button class="rounded-full border border-white/20 px-6 py-3 text-sm text-white" @click="router.push('/')">
            继续逛阅读首页
          </button>
        </div>

        <p class="mt-4 text-sm text-stone-300">{{ secondaryHint }}</p>
      </section>

      <section class="mt-8 grid gap-5 lg:grid-cols-[1.2fr_0.8fr]">
        <div class="rounded-[28px] bg-white p-6 shadow-sm">
          <div class="flex items-center justify-between gap-3">
            <div>
              <p class="text-sm text-stone-500">共享信息</p>
              <h2 class="mt-1 text-2xl font-semibold">适合和阅读端打通的部分</h2>
            </div>
            <button class="rounded-full border border-stone-300 px-4 py-2 text-sm" @click="router.push('/user/profile')">
              查看账号资料
            </button>
          </div>

          <div class="mt-6 grid gap-4 md:grid-cols-2">
            <article class="rounded-2xl border border-stone-200 bg-stone-50 p-4">
              <h3 class="text-base font-semibold">账号资料</h3>
              <p class="mt-2 text-sm text-stone-600">头像、昵称、地区、笔名这些基础身份信息可以继续留在统一账户体系里。</p>
            </article>
            <article class="rounded-2xl border border-stone-200 bg-stone-50 p-4">
              <h3 class="text-base font-semibold">作者身份标识</h3>
              <p class="mt-2 text-sm text-stone-600">在个人资料里展示创作者身份、笔名和公开可见的作者标签，不打断阅读主路径。</p>
            </article>
            <article class="rounded-2xl border border-stone-200 bg-stone-50 p-4">
              <h3 class="text-base font-semibold">作品与反馈摘要</h3>
              <p class="mt-2 text-sm text-stone-600">只展示公开作品概览、读者反馈摘要和通知入口，避免把运营后台暴露到阅读侧。</p>
            </article>
            <article class="rounded-2xl border border-stone-200 bg-stone-50 p-4">
              <h3 class="text-base font-semibold">消息中心的共享部分</h3>
              <p class="mt-2 text-sm text-stone-600">保留和账户、公开作品、互动通知相关的消息；后台事务进入创作中心再看。</p>
            </article>
          </div>
        </div>

        <div class="rounded-[28px] bg-white p-6 shadow-sm">
          <p class="text-sm text-stone-500">创作域隔离</p>
          <h2 class="mt-1 text-2xl font-semibold">只在创作中心处理的内容</h2>

          <div class="mt-6 space-y-3">
            <div class="rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">草稿和未发布内容</div>
            <div class="rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">审核状态与提审流转</div>
            <div class="rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">创作分析后台</div>
            <div class="rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">详细收益、合同、版权资料</div>
            <div class="rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">内部运营工具</div>
          </div>

          <div class="mt-6 rounded-2xl bg-stone-900 p-4 text-sm text-stone-200">
            <p class="font-medium text-white">当前账号</p>
            <p class="mt-2" v-if="loading">正在读取资料...</p>
            <template v-else>
              <p>{{ profile?.name || profile?.username || '未登录用户' }}</p>
              <p class="mt-1">笔名：{{ profile?.pen_name || '未设置' }}</p>
              <p class="mt-1">身份：{{ canOpenCreator ? '创作者' : hasLogin ? '读者账号' : '游客' }}</p>
            </template>
          </div>
        </div>
      </section>
    </div>
  </div>
</template>
