<template>
  <div class="admin-page">
    <div class="toolbar">
      <h2>用户管理</h2>
      <div class="actions">
        <el-input v-model="keyword" placeholder="搜索用户名或邮箱" clearable style="width: 260px" @keyup.enter="loadUsers" />
        <el-button @click="loadUsers">查询</el-button>
        <el-button type="primary" @click="openCreateDialog">新增用户</el-button>
      </div>
    </div>

    <el-card>
      <el-table :data="users" v-loading="loading" border>
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column prop="username" label="用户名" />
        <el-table-column prop="email" label="邮箱" />
        <el-table-column prop="role" label="角色" width="120">
          <template #default="{ row }">
            <el-tag :type="row.role === 'admin' ? 'danger' : 'info'">{{ row.role }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="300">
          <template #default="{ row }">
            <el-button link type="primary" @click="openEditDialog(row)">编辑</el-button>
            <el-button link type="warning" @click="openResetDialog(row)">重置密码</el-button>
            <el-button link type="danger" @click="onDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>

      <div class="pagination">
        <el-pagination
          :current-page="page"
          :page-size="pageSize"
          :total="total"
          layout="total, sizes, prev, pager, next"
          :page-sizes="[10, 20, 50]"
          @current-change="onCurrentPageChange"
          @size-change="onPageSizeChange"
        />
      </div>
    </el-card>

    <el-dialog v-model="createDialogVisible" title="新增用户" width="500px">
      <el-form ref="createFormRef" :model="createForm" :rules="createRules" label-width="90px">
        <el-form-item label="用户名" prop="username"><el-input v-model="createForm.username" /></el-form-item>
        <el-form-item label="邮箱" prop="email"><el-input v-model="createForm.email" /></el-form-item>
        <el-form-item label="密码" prop="password"><el-input v-model="createForm.password" type="password" show-password /></el-form-item>
        <el-form-item label="角色" prop="role">
          <el-select v-model="createForm.role" style="width: 100%">
            <el-option label="普通用户" value="user" />
            <el-option label="管理员" value="admin" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="createLoading" @click="onCreate">创建</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="editDialogVisible" title="编辑用户" width="500px">
      <el-form ref="editFormRef" :model="editForm" :rules="editRules" label-width="90px">
        <el-form-item label="用户名" prop="username"><el-input v-model="editForm.username" /></el-form-item>
        <el-form-item label="邮箱" prop="email"><el-input v-model="editForm.email" /></el-form-item>
        <el-form-item label="角色" prop="role">
          <el-select v-model="editForm.role" style="width: 100%">
            <el-option label="普通用户" value="user" />
            <el-option label="管理员" value="admin" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="editDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="editLoading" @click="onEdit">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="resetDialogVisible" title="重置密码" width="460px">
      <el-form ref="resetFormRef" :model="resetForm" :rules="resetRules" label-width="100px">
        <el-form-item label="新密码" prop="newPassword">
          <el-input v-model="resetForm.newPassword" type="password" show-password />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="resetDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="resetLoading" @click="onResetPassword">确认重置</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox, FormInstance, FormRules } from 'element-plus'
import {
  createAdminUser,
  deleteAdminUser,
  getAdminUsers,
  resetAdminUserPassword,
  updateAdminUser,
} from '../../api/admin'

type UserItem = {
  id: number
  username: string
  email: string
  role: 'user' | 'admin'
}

const users = ref<UserItem[]>([])
const loading = ref(false)
const keyword = ref('')
const page = ref(1)
const pageSize = ref(10)
const total = ref(0)

const createDialogVisible = ref(false)
const createLoading = ref(false)
const createFormRef = ref<FormInstance>()
const createForm = reactive({
  username: '',
  email: '',
  password: '',
  role: 'user' as 'user' | 'admin',
})
const createRules: FormRules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  email: [
    { required: true, message: '请输入邮箱', trigger: 'blur' },
    { type: 'email', message: '邮箱格式不正确', trigger: ['blur', 'change'] },
  ],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }],
  role: [{ required: true, message: '请选择角色', trigger: 'change' }],
}

const editDialogVisible = ref(false)
const editLoading = ref(false)
const editUserId = ref<number | null>(null)
const editFormRef = ref<FormInstance>()
const editForm = reactive({
  username: '',
  email: '',
  role: 'user' as 'user' | 'admin',
})
const editRules: FormRules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  email: [
    { required: true, message: '请输入邮箱', trigger: 'blur' },
    { type: 'email', message: '邮箱格式不正确', trigger: ['blur', 'change'] },
  ],
  role: [{ required: true, message: '请选择角色', trigger: 'change' }],
}

const resetDialogVisible = ref(false)
const resetLoading = ref(false)
const resetUserId = ref<number | null>(null)
const resetFormRef = ref<FormInstance>()
const resetForm = reactive({
  newPassword: '',
})
const resetRules: FormRules = {
  newPassword: [{ required: true, message: '请输入新密码', trigger: 'blur' }],
}

const loadUsers = async () => {
  loading.value = true
  try {
    const res = await getAdminUsers({
      page: page.value,
      page_size: pageSize.value,
      keyword: keyword.value || undefined,
    })
    users.value = res.users || []
    total.value = res.pagination?.total || 0
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载用户列表失败')
  } finally {
    loading.value = false
  }
}

const onCurrentPageChange = (value: number) => {
  page.value = value
  loadUsers()
}

const onPageSizeChange = (value: number) => {
  pageSize.value = value
  page.value = 1
  loadUsers()
}

const openCreateDialog = () => {
  createForm.username = ''
  createForm.email = ''
  createForm.password = ''
  createForm.role = 'user'
  createDialogVisible.value = true
}

const onCreate = async () => {
  if (!createFormRef.value) return
  createFormRef.value.validate(async (valid) => {
    if (!valid) return
    createLoading.value = true
    try {
      await createAdminUser(createForm)
      ElMessage.success('用户创建成功')
      createDialogVisible.value = false
      loadUsers()
    } catch (error: any) {
      ElMessage.error(error?.response?.data?.error || '创建失败')
    } finally {
      createLoading.value = false
    }
  })
}

const openEditDialog = (row: UserItem) => {
  editUserId.value = row.id
  editForm.username = row.username
  editForm.email = row.email
  editForm.role = row.role
  editDialogVisible.value = true
}

const onEdit = async () => {
  const userId = editUserId.value
  if (!editFormRef.value || userId == null) return
  editFormRef.value.validate(async (valid) => {
    if (!valid) return
    editLoading.value = true
    try {
      await updateAdminUser(userId, {
        username: editForm.username,
        email: editForm.email,
        role: editForm.role,
      })
      ElMessage.success('用户更新成功')
      editDialogVisible.value = false
      loadUsers()
    } catch (error: any) {
      ElMessage.error(error?.response?.data?.error || '更新失败')
    } finally {
      editLoading.value = false
    }
  })
}

const openResetDialog = (row: UserItem) => {
  resetUserId.value = row.id
  resetForm.newPassword = ''
  resetDialogVisible.value = true
}

const onResetPassword = async () => {
  const userId = resetUserId.value
  if (!resetFormRef.value || userId === null) return
  resetFormRef.value.validate(async (valid) => {
    if (!valid) return
    resetLoading.value = true
    try {
      await resetAdminUserPassword(userId, resetForm.newPassword)
      ElMessage.success('密码重置成功')
      resetDialogVisible.value = false
    } catch (error: any) {
      ElMessage.error(error?.response?.data?.error || '重置失败')
    } finally {
      resetLoading.value = false
    }
  })
}

const onDelete = async (row: UserItem) => {
  try {
    await ElMessageBox.confirm(`确认删除用户 "${row.username}" 吗？`, '提示', {
      type: 'warning',
    })
    await deleteAdminUser(row.id)
    ElMessage.success('删除成功')
    loadUsers()
  } catch (error: any) {
    if (error !== 'cancel' && error !== 'close') {
      ElMessage.error(error?.response?.data?.error || '删除失败')
    }
  }
}

onMounted(() => {
  loadUsers()
})
</script>

<style scoped>
.admin-page {
  padding: 20px;
}

.toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.actions {
  display: flex;
  gap: 12px;
}

.pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: 16px;
}
</style>
