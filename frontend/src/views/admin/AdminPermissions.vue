<template>
  <div class="admin-page">
    <div class="toolbar">
      <div>
        <h2>权限管理</h2>
        <p class="toolbar-tip">创建和维护权限项，支持重复名称提示与快速检索。</p>
      </div>
      <div class="actions">
        <el-input v-model="keyword" placeholder="搜索权限名或描述" clearable style="width: 260px" />
        <el-button @click="page = 1">重置</el-button>
        <el-button type="primary" @click="openCreateDialog">新增权限</el-button>
      </div>
    </div>

    <el-card>
      <el-table :data="pagedPermissions" v-loading="loading" border empty-text="暂无权限数据">
        <el-table-column prop="name" label="权限名称" min-width="220" />
        <el-table-column prop="description" label="描述" min-width="320" show-overflow-tooltip />
      </el-table>

      <div class="pagination">
        <el-pagination
          :current-page="page"
          :page-size="pageSize"
          :total="filteredPermissions.length"
          layout="total, sizes, prev, pager, next"
          :page-sizes="[10, 20, 50]"
          @current-change="page = $event"
          @size-change="onPageSizeChange"
        />
      </div>
    </el-card>

    <el-dialog v-model="dialogVisible" title="新增权限" width="520px">
      <el-form ref="formRef" :model="form" :rules="rules" label-width="90px">
        <el-form-item label="名称" prop="name">
          <el-input v-model="form.name" maxlength="100" />
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
import { ElMessage, FormInstance, FormRules } from 'element-plus'
import { createRbacPermission, getRbacPermissions, RbacPermission } from '@/api/rbac'

const loading = ref(false)
const submitLoading = ref(false)
const permissions = ref<RbacPermission[]>([])
const keyword = ref('')
const page = ref(1)
const pageSize = ref(10)

const dialogVisible = ref(false)
const formRef = ref<FormInstance>()
const form = reactive({
  name: '',
  description: '',
})

const rules: FormRules = {
  name: [{ required: true, message: '请输入权限名称', trigger: 'blur' }],
}

const filteredPermissions = computed(() => {
  const text = keyword.value.trim().toLowerCase()
  if (!text) return permissions.value
  return permissions.value.filter((item) =>
    [item.name, item.description || ''].some((field) => field.toLowerCase().includes(text))
  )
})

const pagedPermissions = computed(() => {
  const start = (page.value - 1) * pageSize.value
  return filteredPermissions.value.slice(start, start + pageSize.value)
})

const loadPermissions = async () => {
  loading.value = true
  try {
    const res = await getRbacPermissions()
    permissions.value = res.permissions || []
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载权限列表失败')
  } finally {
    loading.value = false
  }
}

const onPageSizeChange = (value: number) => {
  pageSize.value = value
  page.value = 1
}

const openCreateDialog = () => {
  form.name = ''
  form.description = ''
  dialogVisible.value = true
}

const onSubmit = async () => {
  if (!formRef.value) return
  await formRef.value.validate(async (valid) => {
    if (!valid) return
    submitLoading.value = true
    try {
      await createRbacPermission(form)
      ElMessage.success('权限创建成功')
      dialogVisible.value = false
      await loadPermissions()
    } catch (error: any) {
      ElMessage.error(error?.response?.data?.error || '权限名称可能已存在')
    } finally {
      submitLoading.value = false
    }
  })
}

onMounted(loadPermissions)
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
