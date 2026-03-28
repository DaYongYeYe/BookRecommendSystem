<template>
  <div class="admin-page">
    <div class="toolbar">
      <div>
        <h2>角色管理</h2>
        <p class="toolbar-tip">维护角色基础信息，并查看角色绑定的权限数与用户数。</p>
      </div>
      <div class="actions">
        <el-input v-model="keyword" placeholder="搜索角色名或描述" clearable style="width: 260px" />
        <el-button @click="page = 1">重置</el-button>
        <el-button type="primary" @click="openCreateDialog">新增角色</el-button>
      </div>
    </div>

    <el-card>
      <el-table :data="pagedRoles" v-loading="loading" border empty-text="暂无角色数据">
        <el-table-column prop="name" label="角色名称" min-width="180" />
        <el-table-column prop="description" label="描述" min-width="260" show-overflow-tooltip />
        <el-table-column prop="permission_count" label="绑定权限数" width="120" />
        <el-table-column prop="user_count" label="绑定用户数" width="120" />
        <el-table-column label="操作" width="220" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="openEditDialog(row)">编辑</el-button>
            <el-button link type="danger" @click="onDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>

      <div class="pagination">
        <el-pagination
          :current-page="page"
          :page-size="pageSize"
          :total="filteredRoles.length"
          layout="total, sizes, prev, pager, next"
          :page-sizes="[10, 20, 50]"
          @current-change="page = $event"
          @size-change="onPageSizeChange"
        />
      </div>
    </el-card>

    <el-dialog v-model="dialogVisible" :title="editingRoleId ? '编辑角色' : '新增角色'" width="520px">
      <el-form ref="formRef" :model="form" :rules="rules" label-width="90px">
        <el-form-item label="名称" prop="name">
          <el-input v-model="form.name" maxlength="80" />
        </el-form-item>
        <el-form-item label="描述" prop="description">
          <el-input v-model="form.description" type="textarea" :rows="4" maxlength="255" show-word-limit />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="submitLoading" @click="onSubmit">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox, FormInstance, FormRules } from 'element-plus'
import { createRbacRole, deleteRbacRole, getRbacRoles, RbacRole, updateRbacRole } from '@/api/rbac'

const loading = ref(false)
const submitLoading = ref(false)
const roles = ref<RbacRole[]>([])
const keyword = ref('')
const page = ref(1)
const pageSize = ref(10)

const dialogVisible = ref(false)
const editingRoleId = ref<number | null>(null)
const formRef = ref<FormInstance>()
const form = reactive({
  name: '',
  description: '',
})

const rules: FormRules = {
  name: [{ required: true, message: '请输入角色名称', trigger: 'blur' }],
}

const filteredRoles = computed(() => {
  const text = keyword.value.trim().toLowerCase()
  if (!text) return roles.value
  return roles.value.filter((role) =>
    [role.name, role.description || ''].some((field) => field.toLowerCase().includes(text))
  )
})

const pagedRoles = computed(() => {
  const start = (page.value - 1) * pageSize.value
  return filteredRoles.value.slice(start, start + pageSize.value)
})

const loadRoles = async () => {
  loading.value = true
  try {
    const res = await getRbacRoles()
    roles.value = res.roles || []
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载角色列表失败')
  } finally {
    loading.value = false
  }
}

const onPageSizeChange = (value: number) => {
  pageSize.value = value
  page.value = 1
}

const openCreateDialog = () => {
  editingRoleId.value = null
  form.name = ''
  form.description = ''
  dialogVisible.value = true
}

const openEditDialog = (role: RbacRole) => {
  editingRoleId.value = role.id
  form.name = role.name
  form.description = role.description || ''
  dialogVisible.value = true
}

const onSubmit = async () => {
  if (!formRef.value) return
  await formRef.value.validate(async (valid) => {
    if (!valid) return
    submitLoading.value = true
    try {
      if (editingRoleId.value) {
        await updateRbacRole(editingRoleId.value, form)
        ElMessage.success('角色更新成功')
      } else {
        await createRbacRole(form)
        ElMessage.success('角色创建成功')
      }
      dialogVisible.value = false
      await loadRoles()
    } catch (error: any) {
      ElMessage.error(error?.response?.data?.error || '保存角色失败')
    } finally {
      submitLoading.value = false
    }
  })
}

const onDelete = async (role: RbacRole) => {
  const hasBindings = Number(role.user_count || 0) > 0
  try {
    await ElMessageBox.confirm(
      hasBindings
        ? `角色“${role.name}”当前仍绑定用户，后端会阻止删除，是否继续尝试？`
        : `确认删除角色“${role.name}”吗？`,
      '删除确认',
      { type: 'warning' }
    )
    await deleteRbacRole(role.id)
    ElMessage.success('角色删除成功')
    await loadRoles()
  } catch (error: any) {
    if (error !== 'cancel' && error !== 'close') {
      ElMessage.error(error?.response?.data?.error || '删除角色失败，可能仍存在用户绑定')
    }
  }
}

onMounted(loadRoles)
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
  gap: 16px;
}

.toolbar-tip {
  margin: 6px 0 0;
  color: #909399;
  font-size: 13px;
}

.actions {
  display: flex;
  gap: 12px;
  align-items: center;
}

.pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: 16px;
}
</style>
