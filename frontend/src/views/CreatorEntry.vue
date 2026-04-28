<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { getToken } from '@/api/request'
import { getUserProfile, type UserProfile } from '@/api/user'
import { getCreatorApplication, submitCreatorApplication, type CreatorApplicationItem } from '@/api/creator'
import { USER_PROFILE_HUB_ROUTE_NAME } from '@/constants/routes'
import { isCreatorToken } from '@/utils/auth'

const router = useRouter()
const profile = ref<UserProfile | null>(null)
const loading = ref(false)
const applicationLoading = ref(false)
const applySubmitting = ref(false)
const applyReason = ref('')
const application = ref<CreatorApplicationItem | null>(null)

const hasLogin = computed(() => Boolean(getToken()))
const canOpenCreator = computed(() => {
  if (profile.value?.role) return profile.value.role === 'creator'
  return isCreatorToken()
})
const canApply = computed(() => hasLogin.value && !canOpenCreator.value && (!application.value || application.value.status !== 'pending'))

const primaryActionLabel = computed(() => {
  if (canOpenCreator.value) return '进入创作中心'
  if (hasLogin.value) return '提交创作者申请'
  return '登录后继续'
})

const secondaryHint = computed(() => {
  if (canOpenCreator.value) {
    return '你已经具备创作者身份，创作后台会以独立导航承载稿件、章节和创作数据。'
  }
  if (hasLogin.value) {
    return '当前账号以阅读身份为主。可先完善资料并提交创作者申请，审核通过后自动开通创作中心。'
  }
  return '先登录账号，再进入作者准备流程。'
})

const applicationStatusLabel = computed(() => {
  const status = application.value?.status
  if (status === 'pending') return '审核中'
  if (status === 'approved') return '已通过'
  if (status === 'rejected') return '已驳回'
  return '未申请'
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

async function loadApplication() {
  if (!hasLogin.value || canOpenCreator.value) return
  applicationLoading.value = true
  try {
    const res = await getCreatorApplication()
    application.value = res.application || null
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载申请状态失败')
  } finally {
    applicationLoading.value = false
  }
}

async function submitApply() {
  if (!hasLogin.value) {
    router.push({ path: '/login', query: { redirect: '/creator-center' } })
    return
  }
  if (!canApply.value) return
  const reason = applyReason.value.trim()
  if (reason.length < 10) {
    ElMessage.warning('申请说明至少 10 个字')
    return
  }
  applySubmitting.value = true
  try {
    const res = await submitCreatorApplication({ apply_reason: reason })
    application.value = res.application
    ElMessage.success('申请已提交，请等待审核')
    applyReason.value = ''
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '提交申请失败')
  } finally {
    applySubmitting.value = false
  }
}

function handlePrimaryAction() {
  if (canOpenCreator.value) {
    router.push('/creator/works')
    return
  }

  if (!hasLogin.value) {
    router.push({
      path: '/login',
      query: { redirect: '/creator-center' },
    })
    return
  }

  const status = application.value?.status
  if (status === 'pending') {
    ElMessage.info('申请正在审核中，请耐心等待')
    return
  }
  if (status === 'approved') {
    ElMessage.info('申请已通过，请重新登录后进入创作中心')
    return
  }
  router.push({ name: USER_PROFILE_HUB_ROUTE_NAME })
}

onMounted(async () => {
  await loadProfile()
  await loadApplication()
})
</script>

<template>
  <div class="min-h-screen bg-[linear-gradient(180deg,#f5f5f4_0%,#ecfccb_100%)] px-4 py-10 text-stone-900">
    <div class="mx-auto max-w-6xl">
      <div class="mb-6 flex flex-wrap items-center justify-between gap-3">
        <button class="rounded-full border border-stone-300 bg-white px-4 py-2 text-sm" @click="router.push('/')">
          返回阅读端
        </button>
        <button
          class="rounded-full border border-stone-300 bg-white px-4 py-2 text-sm"
          @click="router.push({ name: USER_PROFILE_HUB_ROUTE_NAME })"
        >
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
            <button
              class="rounded-full border border-stone-300 px-4 py-2 text-sm"
              @click="router.push({ name: USER_PROFILE_HUB_ROUTE_NAME })"
            >
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

          <div v-if="hasLogin && !canOpenCreator" class="mt-6 rounded-2xl border border-stone-200 bg-stone-50 p-4 text-sm">
            <div class="flex items-center justify-between gap-3">
              <p class="font-medium text-stone-900">创作者申请状态</p>
              <span class="rounded-full bg-white px-3 py-1 text-xs text-stone-600">{{ applicationStatusLabel }}</span>
            </div>
            <p v-if="applicationLoading" class="mt-2 text-stone-500">正在加载申请信息...</p>
            <template v-else>
              <p class="mt-2 text-stone-600">提交申请后将由后台审核，审核通过会自动开通创作者角色。</p>
              <p v-if="application?.review_comment" class="mt-2 text-amber-700">审核备注：{{ application.review_comment }}</p>
              <textarea
                v-if="canApply"
                v-model="applyReason"
                class="mt-3 w-full rounded-xl border border-stone-300 bg-white px-3 py-2 text-sm outline-none focus:border-stone-500"
                rows="3"
                maxlength="1000"
                placeholder="请填写申请说明（至少 10 个字），例如你的创作方向、更新计划等"
              />
              <button
                v-if="canApply"
                class="mt-3 rounded-full bg-stone-900 px-4 py-2 text-xs text-white disabled:opacity-60"
                :disabled="applySubmitting"
                @click="submitApply"
              >
                {{ applySubmitting ? '提交中...' : '提交创作者申请' }}
              </button>
            </template>
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
