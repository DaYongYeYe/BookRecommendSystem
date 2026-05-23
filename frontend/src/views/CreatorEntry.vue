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
  if (profile.value) return profile.value.is_creator === true
  return isCreatorToken()
})
const canApply = computed(() => hasLogin.value && profile.value?.role === 'user' && !canOpenCreator.value && (!application.value || application.value.status !== 'pending'))

const currentStep = computed(() => {
  if (canOpenCreator.value) return 3
  if (application.value?.status === 'approved') return 3
  if (application.value?.status === 'pending') return 2
  if (hasLogin.value) return 1
  return 0
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
  const el = document.getElementById('apply-section')
  if (el) el.scrollIntoView({ behavior: 'smooth' })
}

onMounted(async () => {
  await loadProfile()
  if (canOpenCreator.value) {
    router.replace('/creator/works')
    return
  }
  await loadApplication()
})
</script>

<template>
  <div class="entry-page">
    <!-- Hero -->
    <section class="hero">
      <div class="hero-content">
        <span class="hero-badge">Creator Center</span>
        <h1 class="hero-title">在这里开始你的创作之旅</h1>
        <p class="hero-desc">管理作品、发布章节、查看数据，创作中心为你提供完整的写作工具链。</p>
        <div class="hero-actions">
          <button class="btn btn-primary btn-lg" @click="handlePrimaryAction">
            {{ canOpenCreator ? '进入创作中心' : hasLogin ? '开始申请' : '登录并申请' }}
          </button>
          <button class="btn btn-outline btn-lg" @click="router.push('/')">返回阅读首页</button>
        </div>
      </div>
    </section>

    <!-- 3-step onboarding -->
    <section class="steps-section">
      <h2 class="section-title">三步成为创作者</h2>
      <div class="steps-grid">
        <div class="step-card" :class="{ done: currentStep >= 1 }">
          <div class="step-number">1</div>
          <h3 class="step-title">登录账号</h3>
          <p class="step-desc">使用已有账号登录，或注册新账号。</p>
          <button v-if="!hasLogin" class="btn btn-sm" @click="router.push({ path: '/login', query: { redirect: '/creator-center' } })">
            去登录
          </button>
          <span v-else class="step-done-label">已完成</span>
        </div>
        <div class="step-connector" :class="{ done: currentStep >= 1 }"></div>
        <div class="step-card" :class="{ done: currentStep >= 2 }">
          <div class="step-number">2</div>
          <h3 class="step-title">提交申请</h3>
          <p class="step-desc">填写创作方向和更新计划，提交创作者申请。</p>
          <span v-if="application?.status === 'pending'" class="step-status-label pending">审核中</span>
          <span v-else-if="application?.status === 'approved'" class="step-done-label">已通过</span>
          <span v-else-if="application?.status === 'rejected'" class="step-status-label rejected">已驳回</span>
        </div>
        <div class="step-connector" :class="{ done: currentStep >= 2 }"></div>
        <div class="step-card" :class="{ done: currentStep >= 3 }">
          <div class="step-number">3</div>
          <h3 class="step-title">开始创作</h3>
          <p class="step-desc">审核通过后即可进入创作中心，发布你的作品。</p>
          <button v-if="canOpenCreator" class="btn btn-sm btn-primary" @click="router.push('/creator/works')">
            进入创作中心
          </button>
        </div>
      </div>
    </section>

    <!-- Apply section (only for logged-in non-creators) -->
    <section v-if="hasLogin && !canOpenCreator" id="apply-section" class="apply-section">
      <div class="apply-card">
        <h2 class="apply-title">创作者申请</h2>
        <p class="apply-desc">请简要说明你的创作方向和更新计划，审核通过后将自动开通创作者身份。</p>

        <div v-if="application?.status === 'rejected'" class="apply-rejected">
          <strong>申请未通过：</strong>{{ application.review_comment || '请修改后重新提交' }}
        </div>

        <div v-if="application?.status === 'pending'" class="apply-pending">
          申请已提交，预计 1-3 个工作日内完成审核，请耐心等待。
        </div>

        <template v-if="canApply">
          <textarea
            v-model="applyReason"
            class="apply-textarea"
            rows="4"
            maxlength="1000"
            placeholder="例如：我计划创作都市情感类小说，预计每周更新 3-5 章，题材以现实主义为主..."
          />
          <div class="apply-hint">至少 10 个字，越详细的描述有助于快速通过审核。</div>
          <button
            class="btn btn-primary"
            :disabled="applySubmitting || applyReason.trim().length < 10"
            @click="submitApply"
          >
            {{ applySubmitting ? '提交中...' : '提交申请' }}
          </button>
        </template>
      </div>
    </section>

    <!-- Current account info -->
    <section v-if="hasLogin" class="account-section">
      <div class="account-card">
        <div class="account-avatar">{{ (profile?.name || profile?.username || '?').charAt(0) }}</div>
        <div class="account-info">
          <div class="account-name">{{ profile?.name || profile?.username || '加载中...' }}</div>
          <div class="account-meta">笔名：{{ profile?.pen_name || '未设置' }} · 身份：{{ canOpenCreator ? '创作者' : '读者' }}</div>
        </div>
        <button class="btn btn-sm" @click="router.push({ name: USER_PROFILE_HUB_ROUTE_NAME })">编辑资料</button>
      </div>
    </section>
  </div>
</template>

<style scoped>
.entry-page {
  min-height: 100vh;
  background: linear-gradient(180deg, #fafaf9 0%, #f5f5f4 100%);
  padding-bottom: 80px;
}

/* Hero */
.hero {
  background: #1c1917;
  color: #fff;
  padding: 64px 24px;
}

.hero-content {
  max-width: 720px;
  margin: 0 auto;
  text-align: center;
}

.hero-badge {
  display: inline-block;
  padding: 4px 16px;
  border-radius: 20px;
  background: rgba(132, 204, 22, 0.2);
  color: #a3e635;
  font-size: 13px;
  letter-spacing: 0.08em;
  margin-bottom: 24px;
}

.hero-title {
  font-size: 36px;
  font-weight: 700;
  line-height: 1.3;
  margin: 0 0 16px;
}

.hero-desc {
  font-size: 16px;
  color: #a8a29e;
  line-height: 1.7;
  margin: 0 0 32px;
}

.hero-actions {
  display: flex;
  gap: 12px;
  justify-content: center;
  flex-wrap: wrap;
}

/* Buttons */
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 12px;
  border: 1px solid #d6d3d1;
  background: #fff;
  color: #44403c;
  font-size: 14px;
  padding: 10px 20px;
  cursor: pointer;
  transition: all 0.2s;
}

.btn:hover {
  background: #f5f5f4;
}

.btn-primary {
  background: #1c1917;
  color: #fff;
  border-color: #1c1917;
}

.btn-primary:hover {
  background: #292524;
}

.btn-primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-outline {
  border-color: rgba(255, 255, 255, 0.3);
  background: transparent;
  color: #fff;
}

.btn-outline:hover {
  background: rgba(255, 255, 255, 0.1);
}

.btn-lg {
  padding: 14px 28px;
  font-size: 15px;
  border-radius: 14px;
}

.btn-sm {
  padding: 6px 14px;
  font-size: 13px;
  border-radius: 10px;
}

/* Steps */
.steps-section {
  max-width: 800px;
  margin: -32px auto 0;
  padding: 0 24px;
}

.section-title {
  text-align: center;
  font-size: 22px;
  font-weight: 700;
  color: #1c1917;
  margin: 0 0 28px;
}

.steps-grid {
  display: flex;
  align-items: center;
  gap: 0;
}

.step-card {
  flex: 1;
  background: #fff;
  border-radius: 20px;
  padding: 24px 20px;
  text-align: center;
  border: 1px solid #e7e5e4;
  transition: all 0.2s;
}

.step-card.done {
  border-color: #a3e635;
  background: linear-gradient(180deg, #fff 0%, #f7fee7 100%);
}

.step-number {
  width: 36px;
  height: 36px;
  border-radius: 50%;
  background: #e7e5e4;
  color: #78716c;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
  font-size: 16px;
  margin-bottom: 12px;
}

.step-card.done .step-number {
  background: #1c1917;
  color: #a3e635;
}

.step-title {
  font-size: 16px;
  font-weight: 600;
  color: #1c1917;
  margin: 0 0 8px;
}

.step-desc {
  font-size: 13px;
  color: #78716c;
  line-height: 1.6;
  margin: 0 0 12px;
}

.step-done-label {
  display: inline-block;
  padding: 4px 12px;
  border-radius: 8px;
  background: #ecfdf5;
  color: #047857;
  font-size: 12px;
  font-weight: 500;
}

.step-status-label {
  display: inline-block;
  padding: 4px 12px;
  border-radius: 8px;
  font-size: 12px;
  font-weight: 500;
}

.step-status-label.pending {
  background: #fef3c7;
  color: #92400e;
}

.step-status-label.rejected {
  background: #fef2f2;
  color: #b91c1c;
}

.step-connector {
  width: 40px;
  height: 2px;
  background: #e7e5e4;
  flex-shrink: 0;
}

.step-connector.done {
  background: #a3e635;
}

/* Apply section */
.apply-section {
  max-width: 600px;
  margin: 40px auto 0;
  padding: 0 24px;
}

.apply-card {
  background: #fff;
  border-radius: 20px;
  padding: 32px;
  border: 1px solid #e7e5e4;
}

.apply-title {
  font-size: 20px;
  font-weight: 700;
  color: #1c1917;
  margin: 0 0 8px;
}

.apply-desc {
  font-size: 14px;
  color: #78716c;
  line-height: 1.6;
  margin: 0 0 20px;
}

.apply-rejected {
  padding: 12px 16px;
  border-radius: 12px;
  background: #fef2f2;
  color: #b91c1c;
  font-size: 13px;
  margin-bottom: 16px;
}

.apply-pending {
  padding: 12px 16px;
  border-radius: 12px;
  background: #fef3c7;
  color: #92400e;
  font-size: 13px;
  margin-bottom: 16px;
}

.apply-textarea {
  width: 100%;
  border: 1px solid #d6d3d1;
  border-radius: 12px;
  padding: 12px 16px;
  font-size: 14px;
  line-height: 1.6;
  resize: vertical;
  outline: none;
  transition: border-color 0.2s;
  font-family: inherit;
  box-sizing: border-box;
}

.apply-textarea:focus {
  border-color: #1c1917;
}

.apply-hint {
  font-size: 12px;
  color: #a8a29e;
  margin: 8px 0 16px;
}

/* Account section */
.account-section {
  max-width: 600px;
  margin: 24px auto 0;
  padding: 0 24px;
}

.account-card {
  background: #fff;
  border-radius: 16px;
  padding: 16px 20px;
  border: 1px solid #e7e5e4;
  display: flex;
  align-items: center;
  gap: 14px;
}

.account-avatar {
  width: 40px;
  height: 40px;
  border-radius: 12px;
  background: #1c1917;
  color: #a3e635;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
  font-size: 16px;
  flex-shrink: 0;
}

.account-info {
  flex: 1;
  min-width: 0;
}

.account-name {
  font-weight: 600;
  color: #1c1917;
  font-size: 14px;
}

.account-meta {
  font-size: 12px;
  color: #78716c;
  margin-top: 2px;
}

/* Responsive */
@media (max-width: 768px) {
  .hero {
    padding: 48px 20px;
  }

  .hero-title {
    font-size: 26px;
  }

  .steps-grid {
    flex-direction: column;
    gap: 12px;
  }

  .step-connector {
    width: 2px;
    height: 20px;
  }
}
</style>
