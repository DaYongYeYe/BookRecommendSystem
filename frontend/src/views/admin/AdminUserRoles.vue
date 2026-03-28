<template>
  <div class="admin-page">
    <div class="toolbar">
      <div>
        <h2>用户角色分配</h2>
        <p class="toolbar-tip">选择用户后，可查看已分配角色、可分配角色，以及该用户当前汇总权限。</p>
      </div>
      <div class="toolbar-right">
        <el-input
          v-model="userKeyword"
          placeholder="搜索用户名或邮箱"
          clearable
          style="width: 260px"
          @keyup.enter="loadUsers"
        />
        <el-button @click="loadUsers">搜索用户</el-button>
        <el-select v-model="selectedUserId" filterable placeholder="请选择用户" style="width: 320px" @change="loadAssignments">
          <el-option
            v-for="user in users"
            :key="user.id"
            :label="`${user.username} (${user.email})`"
            :value="user.id"
          />
        </el-select>
      </div>
    </div>

    <el-empty v-if="!selectedUserId" description="请先选择一个用户" />

    <template v-else>
      <el-card class="summary-card">
        <template #header>当前用户汇总权限</template>
        <div v-if="userPermissions.length" class="permission-tags">
          <el-tag v-for="permission in userPermissions" :key="permission.id" type="info">{{ permission.name }}</el-tag>
        </div>
        <el-empty v-else description="当前用户暂无汇总权限" :image-size="60" />
      </el-card>

      <div class="panels">
        <el-card class="panel">
          <template #header>
            <div class="panel-header">
              <span>已分配角色</span>
              <el-input v-model="assignedKeyword" placeholder="搜索已分配角色" clearable style="width: 220px" />
            </div>
          </template>
          <el-table :data="filteredAssignedRoles" v-loading="loadingAssignments" border empty-text="暂无已分配角色">
            <el-table-column prop="name" label="角色名称" min-width="180" />
            <el-table-column prop="description" label="描述" min-width="220" show-overflow-tooltip />
            <el-table-column label="操作" width="100">
              <template #default="{ row }">
                <el-button link type="danger" @click="onRemoveRole(row)">移除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-card>

        <el-card class="panel">
          <template #header>
            <div class="panel-header">
              <span>可分配角色</span>
              <el-input v-model="availableKeyword" placeholder="搜索可分配角色" clearable style="width: 220px" />
            </div>
          </template>
          <el-table :data="filteredAvailableRoles" v-loading="loadingAssignments" border empty-text="暂无可分配角色">
            <el-table-column prop="name" label="角色名称" min-width="180" />
            <el-table-column prop="description" label="描述" min-width="220" show-overflow-tooltip />
            <el-table-column label="操作" width="100">
              <template #default="{ row }">
                <el-button link type="primary" @click="onAssignRole(row)">分配</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { getAdminUsers } from '@/api/admin'
import {
  assignRoleToUser,
  getRbacRoles,
  getUserPermissions,
  getUserRoles,
  RbacPermission,
  RbacRole,
  removeRoleFromUser,
} from '@/api/rbac'

type UserItem = {
  id: number
  username: string
  email: string
  role: string
  is_super_admin?: boolean
}

const users = ref<UserItem[]>([])
const roles = ref<RbacRole[]>([])
const selectedUserId = ref<number | null>(null)
const userKeyword = ref('')
const assignedRoles = ref<RbacRole[]>([])
const userPermissions = ref<RbacPermission[]>([])
const loadingAssignments = ref(false)
const assignedKeyword = ref('')
const availableKeyword = ref('')

const matches = (value: string, text: string) => value.toLowerCase().includes(text.toLowerCase())

const availableRoles = computed(() => {
  const assignedIds = new Set(assignedRoles.value.map((item) => item.id))
  return roles.value.filter((item) => !assignedIds.has(item.id))
})

const filteredAssignedRoles = computed(() => {
  const text = assignedKeyword.value.trim()
  if (!text) return assignedRoles.value
  return assignedRoles.value.filter((item) =>
    [item.name, item.description || ''].some((field) => matches(field, text))
  )
})

const filteredAvailableRoles = computed(() => {
  const text = availableKeyword.value.trim()
  if (!text) return availableRoles.value
  return availableRoles.value.filter((item) =>
    [item.name, item.description || ''].some((field) => matches(field, text))
  )
})

const loadUsers = async () => {
  try {
    const res = await getAdminUsers({ page: 1, page_size: 100, keyword: userKeyword.value || undefined })
    users.value = res.users || []
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载用户列表失败')
  }
}

const loadRoles = async () => {
  try {
    const res = await getRbacRoles()
    roles.value = res.roles || []
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载角色列表失败')
  }
}

const loadAssignments = async () => {
  if (!selectedUserId.value) {
    assignedRoles.value = []
    userPermissions.value = []
    return
  }
  loadingAssignments.value = true
  try {
    const [roleRes, permissionRes] = await Promise.all([
      getUserRoles(selectedUserId.value),
      getUserPermissions(selectedUserId.value),
    ])
    assignedRoles.value = roleRes.roles || []
    userPermissions.value = permissionRes.permissions || []
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载用户角色失败')
  } finally {
    loadingAssignments.value = false
  }
}

const onAssignRole = async (role: RbacRole) => {
  if (!selectedUserId.value) return
  try {
    await assignRoleToUser(selectedUserId.value, role.id)
    ElMessage.success('角色分配成功')
    await loadAssignments()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '角色已分配或分配失败')
  }
}

const onRemoveRole = async (role: RbacRole) => {
  if (!selectedUserId.value) return
  try {
    await removeRoleFromUser(selectedUserId.value, role.id)
    ElMessage.success('角色移除成功')
    await loadAssignments()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '移除失败，可能触发了最后管理员保护规则')
  }
}

onMounted(async () => {
  await Promise.all([loadUsers(), loadRoles()])
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
  gap: 16px;
}

.toolbar-tip {
  margin: 6px 0 0;
  color: #909399;
  font-size: 13px;
}

.toolbar-right {
  display: flex;
  gap: 12px;
  align-items: center;
  flex-wrap: wrap;
  justify-content: flex-end;
}

.summary-card {
  margin-bottom: 16px;
}

.permission-tags {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
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
