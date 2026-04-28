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
            <el-tag :type="roleTagType(row.role)">{{ row.role }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="超级管理员" width="120">
          <template #default="{ row }">
            <el-tag :type="row.is_super_admin ? 'danger' : 'info'">{{ row.is_super_admin ? '是' : '否' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="tenant_id" label="租户" width="90" />
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

    <el-card class="mt16">
      <template #header>
        <div class="toolbar">
          <h3>创作者入驻申请</h3>
          <div class="actions">
            <el-input v-model="appKeyword" placeholder="搜索申请人用户名或邮箱" clearable style="width: 240px" @keyup.enter="loadCreatorApplications" />
            <el-select v-model="appStatus" placeholder="状态筛选" clearable style="width: 140px" @change="loadCreatorApplications">
              <el-option label="待审核" value="pending" />
              <el-option label="已通过" value="approved" />
              <el-option label="已驳回" value="rejected" />
            </el-select>
            <el-button @click="loadCreatorApplications">刷新</el-button>
          </div>
        </div>
      </template>
      <el-table :data="creatorApplications" v-loading="appLoading" border>
        <el-table-column prop="id" label="申请ID" width="90" />
        <el-table-column label="申请人" min-width="180">
          <template #default="{ row }">
            <div>{{ row.username || '-' }}</div>
            <div class="sub">{{ row.email || '-' }}</div>
          </template>
        </el-table-column>
        <el-table-column prop="apply_reason" label="申请说明" min-width="280" />
        <el-table-column label="状态" width="110">
          <template #default="{ row }">
            <el-tag :type="applicationTagType(row.status)">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="review_comment" label="审核备注" min-width="200" />
        <el-table-column label="审核信息" min-width="180">
          <template #default="{ row }">
            <div>{{ row.reviewed_by_name || '-' }}</div>
            <div class="sub">{{ row.reviewed_at || '-' }}</div>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="160">
          <template #default="{ row }">
            <el-button link type="success" :disabled="row.status !== 'pending'" @click="onReviewApplication(row, 'approve')">通过</el-button>
            <el-button link type="danger" :disabled="row.status !== 'pending'" @click="onReviewApplication(row, 'reject')">驳回</el-button>
          </template>
        </el-table-column>
      </el-table>
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
            <el-option label="创作者" value="creator" />
            <el-option label="编辑" value="editor" />
          </el-select>
        </el-form-item>
        <el-form-item label="超级管理员">
          <el-switch v-model="createForm.is_super_admin" :disabled="!canManageSuperAdmin || createForm.role !== 'admin'" />
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
            <el-option label="创作者" value="creator" />
            <el-option label="编辑" value="editor" />
          </el-select>
        </el-form-item>
        <el-form-item label="超级管理员">
          <el-switch v-model="editForm.is_super_admin" :disabled="!canManageSuperAdmin || editForm.role !== 'admin'" />
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
  getAdminCreatorApplications,
  getAdminUsers,
  reviewAdminCreatorApplication,
  resetAdminUserPassword,
  updateAdminUser,
} from '../../api/admin'
import { isSuperAdminToken } from '../../utils/auth'

type UserRole = 'user' | 'admin' | 'creator' | 'editor'

type UserItem = {
  id: number
  username: string
  email: string
  role: UserRole
  is_super_admin?: boolean
  tenant_id?: number
}

type CreatorApplicationItem = {
  id: number
  user_id: number
  status: 'pending' | 'approved' | 'rejected' | string
  username?: string | null
  email?: string | null
  apply_reason?: string | null
  review_comment?: string | null
  reviewed_by_name?: string | null
  created_at?: string | null
  reviewed_at?: string | null
}
const canManageSuperAdmin = isSuperAdminToken()

const users = ref<UserItem[]>([])
const loading = ref(false)
const keyword = ref('')
const page = ref(1)
const pageSize = ref(10)
const total = ref(0)
const appLoading = ref(false)
const appStatus = ref('')
const appKeyword = ref('')
const creatorApplications = ref<CreatorApplicationItem[]>([])

const createDialogVisible = ref(false)
const createLoading = ref(false)
const createFormRef = ref<FormInstance>()
const createForm = reactive({
  username: '',
  email: '',
  password: '',
  role: 'user' as UserRole,
  is_super_admin: false,
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
  role: 'user' as UserRole,
  is_super_admin: false,
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

const roleTagType = (role: UserRole) => {
  if (role === 'admin') return 'danger'
  if (role === 'creator') return 'success'
  if (role === 'editor') return 'warning'
  return 'info'
}

const applicationTagType = (status: string) => {
  if (status === 'approved') return 'success'
  if (status === 'rejected') return 'danger'
  if (status === 'pending') return 'warning'
  return 'info'
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

const loadCreatorApplications = async () => {
  appLoading.value = true
  try {
    const res = await getAdminCreatorApplications({
      status: appStatus.value || undefined,
      keyword: appKeyword.value || undefined,
    })
    creatorApplications.value = res.items || []
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载创作者申请失败')
  } finally {
    appLoading.value = false
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
  createForm.is_super_admin = false
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
  editForm.is_super_admin = !!row.is_super_admin
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
        is_super_admin: editForm.role === 'admin' ? !!editForm.is_super_admin : false,
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
  if (!resetFormRef.value || userId == null) return
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
    await ElMessageBox.confirm(`确认删除用户 "${row.username}" 吗？`, '提示', { type: 'warning' })
    await deleteAdminUser(row.id)
    ElMessage.success('删除成功')
    loadUsers()
  } catch (error: any) {
    if (error !== 'cancel' && error !== 'close') {
      ElMessage.error(error?.response?.data?.error || '删除失败')
    }
  }
}

const onReviewApplication = async (row: CreatorApplicationItem, action: 'approve' | 'reject') => {
  try {
    const { value } = await ElMessageBox.prompt(
      action === 'approve' ? '通过后将自动开通创作者角色，可填写备注（可选）' : '请填写驳回原因（可选）',
      action === 'approve' ? '通过申请' : '驳回申请',
      {
        inputPlaceholder: action === 'approve' ? '例如：请注意版权规范' : '例如：申请说明不足',
        confirmButtonText: '确认',
        cancelButtonText: '取消',
      }
    )
    await reviewAdminCreatorApplication(row.id, {
      action,
      review_comment: (value || '').trim() || undefined,
    })
    ElMessage.success(action === 'approve' ? '已通过申请并开通创作者' : '已驳回申请')
    await Promise.all([loadUsers(), loadCreatorApplications()])
  } catch (error: any) {
    if (error !== 'cancel' && error !== 'close') {
      ElMessage.error(error?.response?.data?.error || '审核失败')
    }
  }
}

onMounted(() => {
  loadUsers()
  loadCreatorApplications()
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

.mt16 {
  margin-top: 16px;
}

.sub {
  color: #909399;
  font-size: 12px;
}
</style>
