<template>
  <div class="admin-page">
    <div class="toolbar">
      <h2>稿件审核</h2>
      <div class="actions">
        <el-select v-model="statusFilter" style="width: 170px" @change="loadManuscripts">
          <el-option label="全部状态" value="" />
          <el-option label="待审核" value="submitted" />
          <el-option label="已通过" value="approved" />
          <el-option label="已驳回" value="rejected" />
          <el-option label="已发布" value="published" />
          <el-option label="草稿" value="draft" />
        </el-select>
        <el-button @click="loadManuscripts">刷新</el-button>
      </div>
    </div>

    <el-card>
      <el-table :data="manuscripts" v-loading="loading" border>
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column prop="title" label="书名" min-width="220" />
        <el-table-column prop="creator_id" label="创作者ID" width="100" />
        <el-table-column prop="status" label="状态" width="120">
          <template #default="{ row }">
            <el-tag :type="statusTagType(row.status)">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="submitted_at" label="提交时间" width="180" />
        <el-table-column prop="reviewed_at" label="审核时间" width="180" />
        <el-table-column label="操作" width="290">
          <template #default="{ row }">
            <el-button link type="primary" @click="onViewDetail(row)">查看</el-button>
            <el-button link type="success" @click="openReviewDialog(row, 'approve')">通过</el-button>
            <el-button link type="danger" @click="openReviewDialog(row, 'reject')">驳回</el-button>
            <el-button
              link
              type="warning"
              :disabled="!['approved', 'submitted'].includes(row.status)"
              @click="onPublish(row)"
            >
              发布
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="reviewDialogVisible" :title="reviewAction === 'approve' ? '审核通过' : '审核驳回'" width="560px">
      <el-form :model="reviewForm" label-width="100px">
        <el-form-item label="审核意见">
          <el-input
            v-model="reviewForm.review_comment"
            type="textarea"
            :rows="5"
            placeholder="可选，填写给创作者的意见"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="reviewDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="reviewLoading" @click="onSubmitReview">确定</el-button>
      </template>
    </el-dialog>

    <el-drawer v-model="detailVisible" title="稿件详情" size="50%">
      <div v-if="activeManuscript" class="detail">
        <h3>{{ activeManuscript.title }}</h3>
        <p><strong>状态:</strong> {{ activeManuscript.status }}</p>
        <p><strong>简介:</strong> {{ activeManuscript.description || '无' }}</p>
        <p><strong>审核意见:</strong> {{ activeManuscript.review_comment || '无' }}</p>
        <el-divider />
        <pre class="content">{{ activeManuscript.content_text || '无正文' }}</pre>
      </div>
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  AdminManuscriptItem,
  getAdminManuscripts,
  publishAdminManuscript,
  reviewAdminManuscript,
} from '@/api/admin'

const loading = ref(false)
const reviewLoading = ref(false)
const manuscripts = ref<AdminManuscriptItem[]>([])
const statusFilter = ref('')

const detailVisible = ref(false)
const activeManuscript = ref<AdminManuscriptItem | null>(null)

const reviewDialogVisible = ref(false)
const reviewAction = ref<'approve' | 'reject'>('approve')
const reviewManuscriptId = ref<number | null>(null)
const reviewForm = reactive({
  review_comment: '',
})

const statusTagType = (status: string) => {
  if (status === 'published') return 'success'
  if (status === 'approved') return 'warning'
  if (status === 'submitted') return 'info'
  if (status === 'rejected') return 'danger'
  return ''
}

const loadManuscripts = async () => {
  loading.value = true
  try {
    const res = await getAdminManuscripts({ status: statusFilter.value || undefined })
    manuscripts.value = res.items || []
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载稿件失败')
  } finally {
    loading.value = false
  }
}

const onViewDetail = (row: AdminManuscriptItem) => {
  activeManuscript.value = row
  detailVisible.value = true
}

const openReviewDialog = (row: AdminManuscriptItem, action: 'approve' | 'reject') => {
  reviewManuscriptId.value = row.id
  reviewAction.value = action
  reviewForm.review_comment = ''
  reviewDialogVisible.value = true
}

const onSubmitReview = async () => {
  if (!reviewManuscriptId.value) return
  reviewLoading.value = true
  try {
    await reviewAdminManuscript(reviewManuscriptId.value, {
      action: reviewAction.value,
      review_comment: reviewForm.review_comment || undefined,
    })
    ElMessage.success('审核完成')
    reviewDialogVisible.value = false
    await loadManuscripts()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '审核失败')
  } finally {
    reviewLoading.value = false
  }
}

const onPublish = async (row: AdminManuscriptItem) => {
  try {
    await ElMessageBox.confirm(`确认发布《${row.title}》吗？发布后将进入读者端。`, '发布确认', { type: 'warning' })
    await publishAdminManuscript(row.id)
    ElMessage.success('发布成功')
    await loadManuscripts()
  } catch (error: any) {
    if (error !== 'cancel' && error !== 'close') {
      ElMessage.error(error?.response?.data?.error || '发布失败')
    }
  }
}

onMounted(() => {
  loadManuscripts()
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

.detail {
  font-size: 14px;
}

.content {
  white-space: pre-wrap;
  background: #f8f8f8;
  padding: 12px;
  border-radius: 8px;
  max-height: 60vh;
  overflow: auto;
}
</style>
