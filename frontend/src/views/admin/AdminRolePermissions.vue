<template>
  <div class="admin-page">
    <div class="toolbar">
      <div>
        <h2>角色权限分配</h2>
        <p class="toolbar-tip">选择角色后，可在“已分配权限”和“可分配权限”之间进行分配与移除。</p>
      </div>
      <div class="selector">
        <el-select v-model="selectedRoleId" filterable placeholder="请选择角色" style="width: 320px" @change="loadSelectedRolePermissions">
          <el-option v-for="role in roles" :key="role.id" :label="role.name" :value="role.id" />
        </el-select>
      </div>
    </div>

    <el-empty v-if="!selectedRoleId" description="请先选择一个角色" />

    <div v-else class="panels">
      <el-card class="panel">
        <template #header>
          <div class="panel-header">
            <span>已分配权限</span>
            <el-input v-model="assignedKeyword" placeholder="搜索已分配权限" clearable style="width: 220px" />
          </div>
        </template>
        <el-table :data="filteredAssignedPermissions" v-loading="loadingAssignments" border empty-text="暂无已分配权限">
          <el-table-column prop="name" label="权限名称" min-width="180" />
          <el-table-column prop="description" label="描述" min-width="220" show-overflow-tooltip />
          <el-table-column label="操作" width="100">
            <template #default="{ row }">
              <el-button link type="danger" @click="onRemovePermission(row)">移除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-card>

      <el-card class="panel">
        <template #header>
          <div class="panel-header">
            <span>可分配权限</span>
            <el-input v-model="availableKeyword" placeholder="搜索可分配权限" clearable style="width: 220px" />
          </div>
        </template>
        <el-table :data="filteredAvailablePermissions" v-loading="loadingAssignments" border empty-text="暂无可分配权限">
          <el-table-column prop="name" label="权限名称" min-width="180" />
          <el-table-column prop="description" label="描述" min-width="220" show-overflow-tooltip />
          <el-table-column label="操作" width="100">
            <template #default="{ row }">
              <el-button link type="primary" @click="onAssignPermission(row)">分配</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-card>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import {
  assignPermissionToRole,
  getRbacPermissions,
  getRbacRoles,
  getRolePermissions,
  RbacPermission,
  RbacRole,
  removePermissionFromRole,
} from '@/api/rbac'

const roles = ref<RbacRole[]>([])
const permissions = ref<RbacPermission[]>([])
const selectedRoleId = ref<number | null>(null)
const assignedPermissions = ref<RbacPermission[]>([])
const loadingAssignments = ref(false)
const assignedKeyword = ref('')
const availableKeyword = ref('')

const matches = (value: string, text: string) => value.toLowerCase().includes(text.toLowerCase())

const availablePermissions = computed(() => {
  const assignedIds = new Set(assignedPermissions.value.map((item) => item.id))
  return permissions.value.filter((item) => !assignedIds.has(item.id))
})

const filteredAssignedPermissions = computed(() => {
  const text = assignedKeyword.value.trim()
  if (!text) return assignedPermissions.value
  return assignedPermissions.value.filter((item) =>
    [item.name, item.description || ''].some((field) => matches(field, text))
  )
})

const filteredAvailablePermissions = computed(() => {
  const text = availableKeyword.value.trim()
  if (!text) return availablePermissions.value
  return availablePermissions.value.filter((item) =>
    [item.name, item.description || ''].some((field) => matches(field, text))
  )
})

const loadBaseData = async () => {
  try {
    const [roleRes, permissionRes] = await Promise.all([getRbacRoles(), getRbacPermissions()])
    roles.value = roleRes.roles || []
    permissions.value = permissionRes.permissions || []
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载角色或权限数据失败')
  }
}

const loadSelectedRolePermissions = async () => {
  if (!selectedRoleId.value) {
    assignedPermissions.value = []
    return
  }
  loadingAssignments.value = true
  try {
    const res = await getRolePermissions(selectedRoleId.value)
    assignedPermissions.value = res.permissions || []
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载角色权限失败')
  } finally {
    loadingAssignments.value = false
  }
}

const onAssignPermission = async (permission: RbacPermission) => {
  if (!selectedRoleId.value) return
  try {
    await assignPermissionToRole(selectedRoleId.value, permission.id)
    ElMessage.success('权限分配成功')
    await loadSelectedRolePermissions()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '权限已分配或分配失败')
  }
}

const onRemovePermission = async (permission: RbacPermission) => {
  if (!selectedRoleId.value) return
  try {
    await removePermissionFromRole(selectedRoleId.value, permission.id)
    ElMessage.success('权限移除成功')
    await loadSelectedRolePermissions()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '移除权限失败')
  }
}

onMounted(loadBaseData)
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

.selector {
  display: flex;
  align-items: center;
}

.panels {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
}

.panel {
  min-width: 0;
}

.panel-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
}

@media (max-width: 960px) {
  .panels {
    grid-template-columns: 1fr;
  }
}
</style>
