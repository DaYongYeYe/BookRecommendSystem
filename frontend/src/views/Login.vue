<template>
  <div class="auth-page">
    <div class="auth-shell">
      <section class="auth-side">
        <p class="eyebrow">Book Recommend</p>
        <h1>先逛到想读的书，再决定要不要登录。</h1>
        <p class="side-copy">
          首次进入可以先浏览推荐、榜单和书籍详情。需要收藏、继续阅读、同步进度时，再回来登录也不迟。
        </p>

        <div class="side-actions">
          <el-button size="large" @click="goGuestExplore">先看看推荐</el-button>
          <el-button size="large" type="primary" plain @click="goHome">回到首页</el-button>
        </div>

        <ul class="side-points">
          <li>登录后可同步书架、阅读进度和个人资料</li>
          <li>忘记密码时可通过邮箱验证码快速重置</li>
          <li>验证码支持点击图片或文字立即更换</li>
        </ul>
      </section>

      <el-card class="auth-card">
        <div class="mode-switch" role="tablist" aria-label="登录注册切换">
          <button class="mode-switch__item is-active" type="button">登录</button>
          <button class="mode-switch__item" type="button" @click="goRegister">注册</button>
        </div>

        <div class="card-header">
          <h2 class="title">欢迎回来</h2>
          <p class="subtitle">输入账号后即可继续阅读、收藏和同步你的个性化推荐。</p>
        </div>

        <el-form ref="formRef" :model="form" :rules="rules" label-position="top">
          <el-form-item label="用户名" prop="username">
            <el-input
              v-model="form.username"
              autocomplete="username"
              placeholder="请输入用户名"
            />
          </el-form-item>

          <el-form-item prop="password">
            <template #label>
              <div class="field-label">
                <span>密码</span>
                <el-link type="primary" :underline="false" @click="openForgotPassword">
                  忘记密码？
                </el-link>
              </div>
            </template>
            <el-input
              v-model="form.password"
              type="password"
              show-password
              autocomplete="current-password"
              placeholder="请输入密码"
            />
          </el-form-item>

          <el-form-item label="验证码" prop="captcha_code">
            <div class="captcha-block">
              <div class="captcha-row">
                <el-input
                  v-model="form.captcha_code"
                  maxlength="4"
                  placeholder="请输入图形验证码"
                />
                <img
                  class="captcha-image"
                  :src="captchaImage"
                  alt="验证码"
                  @click="refreshCaptcha"
                />
              </div>
              <div class="captcha-hint">
                <span>看不清？</span>
                <el-link type="primary" :underline="false" @click="refreshCaptcha">换一张</el-link>
                <span>或直接点击右侧图片刷新。</span>
              </div>
            </div>
          </el-form-item>

          <el-form-item>
            <el-button
              class="submit-button"
              type="primary"
              :loading="loading"
              @click="onSubmit"
            >
              登录
            </el-button>
          </el-form-item>

          <div class="assist-row">
            <span>还没有账号？</span>
            <el-link type="primary" :underline="false" @click="goRegister">立即注册</el-link>
          </div>

          <div class="guest-row">
            <span>只是想先看看内容？</span>
            <el-link type="primary" :underline="false" @click="goGuestExplore">无需登录，先逛逛</el-link>
          </div>
        </el-form>
      </el-card>
    </div>

    <el-dialog
      v-model="forgotDialogVisible"
      title="忘记密码"
      width="460px"
      destroy-on-close
    >
        <el-form ref="resetFormRef" :model="resetForm" :rules="resetRules" label-position="top">
          <el-form-item label="邮箱" prop="email">
            <el-input v-model="resetForm.email" autocomplete="email" placeholder="请输入注册邮箱" />
          </el-form-item>
          <el-form-item label="图形验证码" prop="captcha_code">
            <div class="captcha-block">
              <div class="inline-action-row">
                <el-input v-model="resetForm.captcha_code" maxlength="4" placeholder="发送邮箱验证码前先输入" />
                <img
                  class="captcha-image"
                  :src="resetCaptchaImage"
                  alt="图形验证码"
                  @click="refreshResetCaptcha"
                />
              </div>
              <div class="captcha-hint">
                <span>看不清？</span>
                <el-link type="primary" :underline="false" @click="refreshResetCaptcha">换一张</el-link>
              </div>
            </div>
          </el-form-item>
          <el-form-item label="邮箱验证码" prop="email_code">
            <div class="inline-action-row">
              <el-input v-model="resetForm.email_code" maxlength="6" placeholder="请输入 6 位验证码" />
            <el-button :disabled="resetCountdown > 0" @click="handleSendResetCode">
              {{ resetCountdown > 0 ? `${resetCountdown}s 后重发` : '发送验证码' }}
            </el-button>
          </div>
        </el-form-item>
        <el-form-item label="新密码" prop="password">
          <el-input
            v-model="resetForm.password"
            type="password"
            show-password
            autocomplete="new-password"
            placeholder="请输入新密码"
          />
        </el-form-item>
        <el-form-item label="确认新密码" prop="confirmPassword">
          <el-input
            v-model="resetForm.confirmPassword"
            type="password"
            show-password
            autocomplete="new-password"
            placeholder="请再次输入新密码"
          />
        </el-form-item>
      </el-form>

      <template #footer>
        <div class="dialog-actions">
          <el-button @click="forgotDialogVisible = false">取消</el-button>
          <el-button type="primary" :loading="resetLoading" @click="handleResetPassword">
            重置密码
          </el-button>
        </div>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, FormInstance, FormRules } from 'element-plus'
import { getCaptcha, login, resetPassword, sendEmailCode } from '../api/auth'

const router = useRouter()
const route = useRoute()

const formRef = ref<FormInstance>()
const resetFormRef = ref<FormInstance>()
const loading = ref(false)
const resetLoading = ref(false)
const forgotDialogVisible = ref(false)
const resetCountdown = ref(0)

let resetTimer: number | null = null

const form = reactive({
  username: '',
  password: '',
  captcha_id: '',
  captcha_code: '',
})

const resetForm = reactive({
  email: '',
  captcha_id: '',
  captcha_code: '',
  email_code: '',
  password: '',
  confirmPassword: '',
})

const captchaImage = ref('')
const resetCaptchaImage = ref('')

const rules: FormRules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }],
  captcha_code: [{ required: true, message: '请输入验证码', trigger: 'blur' }],
}

const resetRules: FormRules = {
  email: [
    { required: true, message: '请输入邮箱', trigger: 'blur' },
    { type: 'email', message: '邮箱格式不正确', trigger: ['blur', 'change'] },
  ],
  captcha_code: [{ required: true, message: '请输入图形验证码', trigger: 'blur' }],
  email_code: [{ required: true, message: '请输入邮箱验证码', trigger: 'blur' }],
  password: [{ required: true, message: '请输入新密码', trigger: 'blur' }],
  confirmPassword: [
    { required: true, message: '请再次输入新密码', trigger: 'blur' },
    {
      validator: (_rule, value, callback) => {
        if (value !== resetForm.password) {
          callback(new Error('两次输入的密码不一致'))
        } else {
          callback()
        }
      },
      trigger: ['blur', 'change'],
    },
  ],
}

const clearResetTimer = () => {
  if (resetTimer !== null) {
    window.clearInterval(resetTimer)
    resetTimer = null
  }
}

const startResetCountdown = (seconds: number) => {
  clearResetTimer()
  resetCountdown.value = seconds
  resetTimer = window.setInterval(() => {
    if (resetCountdown.value <= 1) {
      resetCountdown.value = 0
      clearResetTimer()
      return
    }
    resetCountdown.value -= 1
  }, 1000)
}

const refreshCaptcha = async () => {
  const data = await getCaptcha()
  form.captcha_id = data.captcha_id
  form.captcha_code = ''
  captchaImage.value = data.captcha_image
}

const refreshResetCaptcha = async () => {
  const data = await getCaptcha()
  resetForm.captcha_id = data.captcha_id
  resetForm.captcha_code = ''
  resetCaptchaImage.value = data.captcha_image
}

onMounted(async () => {
  try {
    await Promise.all([refreshCaptcha(), refreshResetCaptcha()])
  } catch {
    ElMessage.error('获取验证码失败，请稍后重试')
  }
})

onUnmounted(() => {
  clearResetTimer()
})

const onSubmit = () => {
  if (!formRef.value) return
  formRef.value.validate(async (valid) => {
    if (!valid) return
    loading.value = true
    try {
      await login(form)
      ElMessage.success('登录成功')
      const redirect = (route.query.redirect as string) || '/'
      router.push(redirect)
    } catch (error: any) {
      const msg = error?.response?.data?.error || '登录失败，请检查账号信息'
      ElMessage.error(msg)
      await refreshCaptcha()
    } finally {
      loading.value = false
    }
  })
}

const handleSendResetCode = async () => {
  if (!resetForm.email) {
    ElMessage.warning('请先输入注册邮箱')
    return
  }
  if (!resetForm.captcha_id || !resetForm.captcha_code) {
    ElMessage.warning('请先输入图形验证码')
    return
  }
  try {
    const res = await sendEmailCode({
      email: resetForm.email,
      purpose: 'reset_password',
      captcha_id: resetForm.captcha_id,
      captcha_code: resetForm.captcha_code,
    })
    startResetCountdown(res.resend_seconds || 60)
    ElMessage.success(`验证码已发送到 ${res.masked_email}`)
  } catch (error: any) {
    const msg = error?.response?.data?.error || '发送验证码失败'
    ElMessage.error(msg)
    await refreshResetCaptcha()
  }
}

const handleResetPassword = () => {
  if (!resetFormRef.value) return
  resetFormRef.value.validate(async (valid) => {
    if (!valid) return
    resetLoading.value = true
    try {
      await resetPassword({
        email: resetForm.email,
        email_code: resetForm.email_code,
        password: resetForm.password,
      })
      ElMessage.success('密码已重置，请使用新密码登录')
      forgotDialogVisible.value = false
      resetForm.captcha_code = ''
      resetForm.email_code = ''
      resetForm.password = ''
      resetForm.confirmPassword = ''
      await refreshResetCaptcha()
    } catch (error: any) {
      const msg = error?.response?.data?.error || '重置密码失败'
      ElMessage.error(msg)
    } finally {
      resetLoading.value = false
    }
  })
}

const goRegister = () => {
  router.push('/register')
}

const goHome = () => {
  router.push('/')
}

const goGuestExplore = () => {
  router.push('/recommendations')
}

const openForgotPassword = () => {
  forgotDialogVisible.value = true
}
</script>

<style scoped>
.auth-page {
  min-height: 100vh;
  padding: 32px 20px;
  background:
    radial-gradient(circle at top left, rgba(243, 210, 163, 0.45), transparent 30%),
    linear-gradient(135deg, #f6efe5 0%, #eef3ff 48%, #f7fbf8 100%);
}

.auth-shell {
  max-width: 1080px;
  margin: 0 auto;
  display: grid;
  grid-template-columns: minmax(0, 1.05fr) minmax(360px, 430px);
  gap: 28px;
  align-items: stretch;
}

.auth-side {
  display: flex;
  flex-direction: column;
  justify-content: center;
  padding: 36px 40px;
  border: 1px solid rgba(255, 255, 255, 0.7);
  border-radius: 32px;
  background: rgba(24, 40, 34, 0.88);
  color: #f7f4ef;
  box-shadow: 0 22px 60px rgba(41, 53, 46, 0.16);
}

.eyebrow {
  margin: 0;
  font-size: 13px;
  letter-spacing: 0.24em;
  text-transform: uppercase;
  color: rgba(247, 244, 239, 0.75);
}

.auth-side h1 {
  margin: 16px 0 0;
  font-size: 42px;
  line-height: 1.15;
}

.side-copy {
  margin: 18px 0 0;
  max-width: 520px;
  font-size: 16px;
  line-height: 1.75;
  color: rgba(247, 244, 239, 0.82);
}

.side-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-top: 28px;
}

.side-points {
  margin: 28px 0 0;
  padding-left: 20px;
  display: grid;
  gap: 12px;
  color: rgba(247, 244, 239, 0.88);
  line-height: 1.6;
}

.auth-card {
  border-radius: 32px;
  border: 1px solid rgba(255, 255, 255, 0.72);
  background: rgba(255, 255, 255, 0.9);
  box-shadow: 0 22px 50px rgba(86, 102, 129, 0.12);
}

.mode-switch {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 8px;
  padding: 6px;
  border-radius: 999px;
  background: #f1ede7;
}

.mode-switch__item {
  border: 0;
  border-radius: 999px;
  background: transparent;
  color: #5e5a55;
  font-size: 15px;
  padding: 11px 16px;
  cursor: pointer;
  transition: all 0.2s ease;
}

.mode-switch__item.is-active {
  background: #fff;
  color: #1f2937;
  box-shadow: 0 8px 20px rgba(49, 58, 72, 0.08);
}

.card-header {
  margin: 24px 0 6px;
}

.title {
  margin: 0;
  color: #18221f;
  font-size: 30px;
}

.subtitle {
  margin: 10px 0 0;
  color: #6b7280;
  line-height: 1.7;
}

.field-label {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  width: 100%;
}

.captcha-block {
  width: 100%;
}

.captcha-row,
.inline-action-row {
  width: 100%;
  display: flex;
  gap: 10px;
}

.captcha-image {
  width: 120px;
  min-width: 120px;
  height: 40px;
  border: 1px solid #d8dee8;
  border-radius: 12px;
  background: #fff;
  cursor: pointer;
}

.captcha-hint {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  margin-top: 10px;
  color: #6b7280;
  font-size: 13px;
}

.submit-button {
  width: 100%;
  min-height: 44px;
  border-radius: 14px;
}

.assist-row,
.guest-row {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  color: #6b7280;
  font-size: 14px;
}

.guest-row {
  margin-top: 12px;
}

.dialog-actions {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
}

@media (max-width: 960px) {
  .auth-shell {
    grid-template-columns: 1fr;
  }

  .auth-side {
    padding: 28px;
  }

  .auth-side h1 {
    font-size: 34px;
  }
}

@media (max-width: 640px) {
  .auth-page {
    padding: 16px;
  }

  .auth-side,
  .auth-card {
    border-radius: 24px;
  }

  .captcha-row,
  .inline-action-row {
    flex-direction: column;
  }

  .captcha-image {
    width: 100%;
    height: 48px;
  }
}
</style>
