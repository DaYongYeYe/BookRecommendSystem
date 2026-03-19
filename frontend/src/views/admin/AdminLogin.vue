<template>
  <div class="auth-page">
    <el-card class="auth-card">
      <h2 class="title">后台管理 - 登录</h2>
      <el-form ref="formRef" :model="form" :rules="rules" label-width="90px">
        <el-form-item label="用户名" prop="username">
          <el-input v-model="form.username" autocomplete="username" />
        </el-form-item>
        <el-form-item label="密码" prop="password">
          <el-input v-model="form.password" type="password" show-password autocomplete="current-password" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="loading" style="width: 100%" @click="onSubmit">登录管理端</el-button>
        </el-form-item>
        <el-form-item>
          <div class="footer-text">
            没有管理员账号？
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
import { adminLogin } from '../../api/admin'
import { setToken } from '../../api/request'

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
      const res = await adminLogin(form)
      if (res.token) {
        setToken(res.token)
      }
      ElMessage.success('管理员登录成功')
      const redirect = (route.query.redirect as string) || '/manage/dashboard'
      router.push(redirect)
    } catch (error: any) {
      ElMessage.error(error?.response?.data?.error || '登录失败')
    } finally {
      loading.value = false
    }
  })
}

const goRegister = () => {
  router.push('/manage/register')
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
  width: 420px;
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
