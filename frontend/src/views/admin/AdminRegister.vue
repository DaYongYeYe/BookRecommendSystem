<template>
  <div class="auth-page">
    <el-card class="auth-card">
      <h2 class="title">后台管理 - 注册</h2>
      <el-alert
        type="warning"
        :closable="false"
        show-icon
        title="需要管理员注册码（ADMIN_REGISTER_CODE）"
        style="margin-bottom: 16px"
      />
      <el-form ref="formRef" :model="form" :rules="rules" label-width="110px">
        <el-form-item label="用户名" prop="username">
          <el-input v-model="form.username" autocomplete="username" />
        </el-form-item>
        <el-form-item label="邮箱" prop="email">
          <el-input v-model="form.email" autocomplete="email" />
        </el-form-item>
        <el-form-item label="密码" prop="password">
          <el-input v-model="form.password" type="password" show-password autocomplete="new-password" />
        </el-form-item>
        <el-form-item label="确认密码" prop="confirmPassword">
          <el-input v-model="form.confirmPassword" type="password" show-password autocomplete="new-password" />
        </el-form-item>
        <el-form-item label="管理员注册码" prop="register_code">
          <el-input v-model="form.register_code" />
        </el-form-item>
        <el-form-item label="验证码" prop="captcha_code">
          <div class="captcha-row">
            <el-input v-model="form.captcha_code" maxlength="4" placeholder="请输入验证码" />
            <img class="captcha-image" :src="captchaImage" alt="captcha" @click="refreshCaptcha" />
          </div>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="loading" style="width: 100%" @click="onSubmit">注册管理员</el-button>
        </el-form-item>
        <el-form-item>
          <div class="footer-text">
            已有管理员账号？
            <el-link type="primary" @click="goLogin">去登录</el-link>
          </div>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, FormInstance, FormRules } from 'element-plus'
import { adminRegister, getAdminCaptcha } from '../../api/admin'

const router = useRouter()
const formRef = ref<FormInstance>()
const loading = ref(false)

const form = reactive({
  username: '',
  email: '',
  password: '',
  confirmPassword: '',
  register_code: '',
  captcha_id: '',
  captcha_code: '',
})

const captchaImage = ref('')

const rules: FormRules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  email: [
    { required: true, message: '请输入邮箱', trigger: 'blur' },
    { type: 'email', message: '邮箱格式不正确', trigger: ['blur', 'change'] },
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
  register_code: [{ required: true, message: '请输入管理员注册码', trigger: 'blur' }],
  captcha_code: [{ required: true, message: '请输入验证码', trigger: 'blur' }],
}

const refreshCaptcha = async () => {
  const data = await getAdminCaptcha()
  form.captcha_id = data.captcha_id
  form.captcha_code = ''
  captchaImage.value = data.captcha_image
}

onMounted(async () => {
  try {
    await refreshCaptcha()
  } catch {
    ElMessage.error('获取验证码失败')
  }
})

const onSubmit = () => {
  if (!formRef.value) return
  formRef.value.validate(async (valid) => {
    if (!valid) return
    loading.value = true
    try {
      await adminRegister({
        username: form.username,
        email: form.email,
        password: form.password,
        register_code: form.register_code,
        captcha_id: form.captcha_id,
        captcha_code: form.captcha_code,
      })
      ElMessage.success('管理员注册成功，请登录')
      router.push('/manage/login')
    } catch (error: any) {
      ElMessage.error(error?.response?.data?.error || '注册失败')
      await refreshCaptcha()
    } finally {
      loading.value = false
    }
  })
}

const goLogin = () => {
  router.push('/manage/login')
}
</script>

<style scoped>
.auth-page {
  height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #f5f7fa, #e0ecff);
}

.auth-card {
  width: 460px;
}

.title {
  text-align: center;
  margin-bottom: 24px;
}

.footer-text {
  width: 100%;
  text-align: right;
}

.captcha-row {
  width: 100%;
  display: flex;
  gap: 10px;
}

.captcha-image {
  width: 120px;
  height: 40px;
  border: 1px solid #dcdfe6;
  border-radius: 4px;
  cursor: pointer;
}
</style>
