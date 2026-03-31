<template>
  <div class="auth-page">
    <div class="auth-shell">
      <section class="auth-side">
        <p class="eyebrow">Start Reading</p>
        <h1>先建立账号，之后的阅读轨迹就都能被记住。</h1>
        <p class="side-copy">
          注册后你可以收藏书籍、保存阅读进度、维护个人偏好。若还不想立刻注册，也可以先逛逛推荐区再决定。
        </p>

        <div class="side-actions">
          <el-button size="large" @click="goGuestExplore">先看看推荐</el-button>
          <el-button size="large" type="primary" plain @click="goLogin">已有账号，去登录</el-button>
        </div>

        <ul class="side-points">
          <li>邮箱验证码注册替代原来的注册图形验证码</li>
          <li>验证码支持倒计时重发，操作更接近日常产品习惯</li>
          <li>发送层已预留适配，可后续切换到阿里云或腾讯云</li>
        </ul>
      </section>

      <el-card class="auth-card">
        <div class="mode-switch" role="tablist" aria-label="登录注册切换">
          <button class="mode-switch__item" type="button" @click="goLogin">登录</button>
          <button class="mode-switch__item is-active" type="button">注册</button>
        </div>

        <div class="card-header">
          <h2 class="title">创建你的账号</h2>
          <p class="subtitle">只需几项基础信息，就能保存书架、进度和个性化推荐。</p>
        </div>

        <el-form ref="formRef" :model="form" :rules="rules" label-position="top">
          <el-form-item label="用户名" prop="username">
            <el-input
              v-model="form.username"
              autocomplete="username"
              placeholder="请输入用户名"
            />
          </el-form-item>

          <el-form-item label="邮箱" prop="email">
            <el-input
              v-model="form.email"
              autocomplete="email"
              placeholder="请输入常用邮箱"
            />
          </el-form-item>

          <el-form-item label="图形验证码" prop="captcha_code">
            <div class="captcha-block">
              <div class="inline-action-row">
                <el-input
                  v-model="form.captcha_code"
                  maxlength="4"
                  placeholder="发送邮箱验证码前先输入"
                />
                <img
                  class="captcha-image"
                  :src="captchaImage"
                  alt="图形验证码"
                  @click="refreshCaptcha"
                />
              </div>
              <div class="captcha-hint">
                <span>看不清？</span>
                <el-link type="primary" :underline="false" @click="refreshCaptcha">换一张</el-link>
              </div>
            </div>
          </el-form-item>

          <el-form-item label="邮箱验证码" prop="email_code">
            <div class="inline-action-row">
              <el-input
                v-model="form.email_code"
                maxlength="6"
                placeholder="请输入 6 位验证码"
              />
              <el-button :disabled="countdown > 0" @click="handleSendCode">
                {{ countdown > 0 ? `${countdown}s 后重发` : '发送验证码' }}
              </el-button>
            </div>
          </el-form-item>

          <el-form-item label="年龄" prop="age">
            <el-input-number
              v-model="form.age"
              :min="1"
              :max="120"
              :step="1"
              controls-position="right"
              class="age-input"
            />
          </el-form-item>

          <el-form-item label="密码" prop="password">
            <el-input
              v-model="form.password"
              type="password"
              show-password
              autocomplete="new-password"
              placeholder="请输入密码"
            />
          </el-form-item>

          <el-form-item label="确认密码" prop="confirmPassword">
            <el-input
              v-model="form.confirmPassword"
              type="password"
              show-password
              autocomplete="new-password"
              placeholder="请再次输入密码"
            />
          </el-form-item>

          <el-form-item>
            <el-button
              class="submit-button"
              type="primary"
              :loading="loading"
              @click="onSubmit"
            >
              注册
            </el-button>
          </el-form-item>

          <div class="assist-row">
            <span>已经有账号？</span>
            <el-link type="primary" :underline="false" @click="goLogin">立即登录</el-link>
          </div>

          <div class="guest-row">
            <span>想先体验一下？</span>
            <el-link type="primary" :underline="false" @click="goGuestExplore">先以游客身份浏览</el-link>
          </div>
        </el-form>
      </el-card>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, FormInstance, FormRules } from 'element-plus'
import { getCaptcha, register, sendEmailCode } from '../api/auth'

const router = useRouter()

const formRef = ref<FormInstance>()
const loading = ref(false)
const countdown = ref(0)

let timer: number | null = null

const form = reactive({
  username: '',
  email: '',
  captcha_id: '',
  captcha_code: '',
  email_code: '',
  age: 18,
  password: '',
  confirmPassword: '',
})

const captchaImage = ref('')

const rules: FormRules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  email: [
    { required: true, message: '请输入邮箱', trigger: 'blur' },
    { type: 'email', message: '邮箱格式不正确', trigger: ['blur', 'change'] },
  ],
  captcha_code: [{ required: true, message: '请输入图形验证码', trigger: 'blur' }],
  email_code: [{ required: true, message: '请输入邮箱验证码', trigger: 'blur' }],
  age: [
    { required: true, message: '请输入年龄', trigger: 'change' },
    {
      validator: (_rule, value, callback) => {
        const age = Number(value)
        if (!Number.isInteger(age) || age < 1 || age > 120) {
          callback(new Error('年龄范围需在 1-120'))
        } else {
          callback()
        }
      },
      trigger: ['change', 'blur'],
    },
  ],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }],
  confirmPassword: [
    { required: true, message: '请再次输入密码', trigger: 'blur' },
    {
      validator: (_rule, value, callback) => {
        if (value !== form.password) {
          callback(new Error('两次输入的密码不一致'))
        } else {
          callback()
        }
      },
      trigger: ['blur', 'change'],
    },
  ],
}

const clearTimer = () => {
  if (timer !== null) {
    window.clearInterval(timer)
    timer = null
  }
}

const startCountdown = (seconds: number) => {
  clearTimer()
  countdown.value = seconds
  timer = window.setInterval(() => {
    if (countdown.value <= 1) {
      countdown.value = 0
      clearTimer()
      return
    }
    countdown.value -= 1
  }, 1000)
}

onUnmounted(() => {
  clearTimer()
})

const refreshCaptcha = async () => {
  const data = await getCaptcha()
  form.captcha_id = data.captcha_id
  form.captcha_code = ''
  captchaImage.value = data.captcha_image
}

onMounted(async () => {
  try {
    await refreshCaptcha()
  } catch {
    ElMessage.error('获取图形验证码失败，请稍后重试')
  }
})

const handleSendCode = async () => {
  if (!form.email) {
    ElMessage.warning('请先输入邮箱')
    return
  }
  if (!form.captcha_id || !form.captcha_code) {
    ElMessage.warning('请先输入图形验证码')
    return
  }

  try {
    const res = await sendEmailCode({
      email: form.email,
      purpose: 'register',
      captcha_id: form.captcha_id,
      captcha_code: form.captcha_code,
    })
    startCountdown(res.resend_seconds || 60)
    ElMessage.success(`验证码已发送到 ${res.masked_email}`)
  } catch (error: any) {
    const msg = error?.response?.data?.error || '发送验证码失败'
    ElMessage.error(msg)
    await refreshCaptcha()
  }
}

const onSubmit = () => {
  if (!formRef.value) return
  formRef.value.validate(async (valid) => {
    if (!valid) return
    loading.value = true
    try {
      await register({
        username: form.username,
        email: form.email,
        age: Number(form.age),
        password: form.password,
        email_code: form.email_code,
      })
      ElMessage.success('注册成功，请登录')
      router.push('/login')
    } catch (error: any) {
      const msg = error?.response?.data?.error || '注册失败，请稍后重试'
      ElMessage.error(msg)
    } finally {
      loading.value = false
    }
  })
}

const goLogin = () => {
  router.push('/login')
}

const goGuestExplore = () => {
  router.push('/recommendations')
}
</script>

<style scoped>
.auth-page {
  min-height: 100vh;
  padding: 32px 20px;
  background:
    radial-gradient(circle at top right, rgba(168, 218, 220, 0.38), transparent 28%),
    linear-gradient(135deg, #fff3e9 0%, #eef5ff 52%, #f7fbf8 100%);
}

.auth-shell {
  max-width: 1080px;
  margin: 0 auto;
  display: grid;
  grid-template-columns: minmax(0, 1.05fr) minmax(360px, 440px);
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
  background: rgba(53, 82, 96, 0.9);
  color: #f8fafc;
  box-shadow: 0 22px 60px rgba(71, 95, 116, 0.16);
}

.eyebrow {
  margin: 0;
  font-size: 13px;
  letter-spacing: 0.24em;
  text-transform: uppercase;
  color: rgba(248, 250, 252, 0.74);
}

.auth-side h1 {
  margin: 16px 0 0;
  font-size: 40px;
  line-height: 1.18;
}

.side-copy {
  margin: 18px 0 0;
  max-width: 520px;
  font-size: 16px;
  line-height: 1.75;
  color: rgba(248, 250, 252, 0.84);
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
  color: rgba(248, 250, 252, 0.88);
  line-height: 1.6;
}

.auth-card {
  border-radius: 32px;
  border: 1px solid rgba(255, 255, 255, 0.72);
  background: rgba(255, 255, 255, 0.92);
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
  color: #18222f;
  font-size: 30px;
}

.subtitle {
  margin: 10px 0 0;
  color: #6b7280;
  line-height: 1.7;
}

.age-input {
  width: 100%;
}

.inline-action-row {
  width: 100%;
  display: flex;
  gap: 10px;
}

.captcha-block {
  width: 100%;
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

  .inline-action-row {
    flex-direction: column;
  }

  .captcha-image {
    width: 100%;
    height: 48px;
  }
}
</style>
