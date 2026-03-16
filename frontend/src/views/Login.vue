<template>
  <div class="auth-page">
    <el-card class="auth-card">
      <h2 class="title">图书推荐系统 - 登录</h2>
      <el-form :model="form" :rules="rules" ref="formRef" label-width="80px">
        <el-form-item label="用户名" prop="username">
          <el-input v-model="form.username" autocomplete="username" />
        </el-form-item>
        <el-form-item label="密码" prop="password">
          <el-input
            v-model="form.password"
            type="password"
            show-password
            autocomplete="current-password"
          />
        </el-form-item>
        <el-form-item>
          <el-button
            type="primary"
            :loading="loading"
            style="width: 100%"
            @click="onSubmit"
          >
            登录
          </el-button>
        </el-form-item>
        <el-form-item>
          <div class="footer-text">
            还没有账号？
            <el-link type="primary" @click="goRegister">去注册</el-link>
          </div>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, FormInstance, FormRules } from 'element-plus'
import { login } from '@/api/auth'

const router = useRouter()
const route = useRoute()

const formRef = ref<FormInstance>()
const loading = ref(false)

const form = reactive({
  username: '',
  password: '',
})

const rules: FormRules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }],
}

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
      const msg = error?.response?.data?.error || '登录失败'
      ElMessage.error(msg)
    } finally {
      loading.value = false
    }
  })
}

const goRegister = () => {
  router.push('/register')
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
  width: 400px;
}

.title {
  text-align: center;
  margin-bottom: 24px;
}

.footer-text {
  width: 100%;
  text-align: right;
}
</style>

