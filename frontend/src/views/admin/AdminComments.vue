<template>
  <div class="admin-page">
    <div class="toolbar">
      <h2>评论管理</h2>
      <div class="actions">
        <el-select v-model="typeFilter" style="width: 160px" @change="onFilterChange">
          <el-option label="全部类型" value="" />
          <el-option label="书评" value="book" />
          <el-option label="划线评论" value="highlight" />
        </el-select>
        <el-input
          v-model="keyword"
          placeholder="搜索评论内容/作者/书名"
          clearable
          style="width: 280px"
          @keyup.enter="loadComments"
        />
        <el-button @click="loadComments">查询</el-button>
      </div>
    </div>

    <el-card>
      <el-table :data="comments" v-loading="loading" border>
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column label="类型" width="110">
          <template #default="{ row }">
            <el-tag :type="row.type === 'book' ? 'primary' : 'warning'">
              {{ row.type === 'book' ? '书评' : '划线评论' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="book_title" label="所属图书" min-width="200">
          <template #default="{ row }">
            <span>{{ row.book_title || `图书 #${row.book_id || '-'}` }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="author" label="作者" width="130" />
        <el-table-column prop="content" label="内容" min-width="320" show-overflow-tooltip />
        <el-table-column label="违规" width="120">
          <template #default="{ row }">
            <el-tag :type="row.is_violation ? 'danger' : 'info'">{{ row.is_violation ? '已违规' : '正常' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="时间" width="180">
          <template #default="{ row }">{{ formatDate(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="220" fixed="right">
          <template #default="{ row }">
            <el-button
              link
              :type="row.is_violation ? 'success' : 'warning'"
              @click="onToggleViolation(row)"
            >
              {{ row.is_violation ? '取消违规' : '标记违规' }}
            </el-button>
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
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { AdminCommentItem, deleteAdminComment, getAdminComments, setAdminCommentViolation } from '../../api/admin'

const comments = ref<AdminCommentItem[]>([])
const loading = ref(false)
const keyword = ref('')
const typeFilter = ref('')
const page = ref(1)
const pageSize = ref(10)
const total = ref(0)

const formatDate = (value?: string | null) => {
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString()
}

const loadComments = async () => {
  loading.value = true
  try {
    const res = await getAdminComments({
      page: page.value,
      page_size: pageSize.value,
      keyword: keyword.value || undefined,
      type: typeFilter.value || undefined,
    })
    comments.value = res.items || []
    total.value = res.pagination?.total || 0
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载评论列表失败')
  } finally {
    loading.value = false
  }
}

const onFilterChange = () => {
  page.value = 1
  loadComments()
}

const onCurrentPageChange = (value: number) => {
  page.value = value
  loadComments()
}

const onPageSizeChange = (value: number) => {
  pageSize.value = value
  page.value = 1
  loadComments()
}

const onDelete = async (row: AdminCommentItem) => {
  const typeLabel = row.type === 'book' ? '书评' : '划线评论'
  try {
    await ElMessageBox.confirm(`确认删除该${typeLabel}吗？`, '提示', { type: 'warning' })
    await deleteAdminComment(row.type, row.id)
    ElMessage.success('删除成功')
    loadComments()
  } catch (error: any) {
    if (error !== 'cancel' && error !== 'close') {
      ElMessage.error(error?.response?.data?.error || '删除失败')
    }
  }
}

const onToggleViolation = async (row: AdminCommentItem) => {
  try {
    if (row.is_violation) {
      await setAdminCommentViolation(row.type, row.id, { is_violation: false })
      ElMessage.success('已取消违规标记')
      await loadComments()
      return
    }

    const result = await ElMessageBox.prompt('请输入违规原因（可选）', '标记违规', {
      inputPlaceholder: '如：人身攻击、垃圾广告',
      confirmButtonText: '确认标记',
      cancelButtonText: '取消',
    })
    await setAdminCommentViolation(row.type, row.id, {
      is_violation: true,
      violation_reason: result.value || undefined,
    })
    ElMessage.success('已标记为违规')
    await loadComments()
  } catch (error: any) {
    if (error !== 'cancel' && error !== 'close') {
      ElMessage.error(error?.response?.data?.error || '操作失败')
    }
  }
}

onMounted(() => {
  loadComments()
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
