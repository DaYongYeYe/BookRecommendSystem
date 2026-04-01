<template>
  <div class="admin-page">
    <div class="toolbar">
      <h2>作品资料审核</h2>
      <div class="actions">
        <el-input v-model="keyword" placeholder="搜索作品名或作者" clearable style="width: 240px" @keyup.enter="loadItems" />
        <el-select v-model="auditStatus" style="width: 160px" @change="loadItems">
          <el-option label="全部审核状态" value="" />
          <el-option label="草稿" value="draft" />
          <el-option label="待审核" value="pending" />
          <el-option label="已通过" value="approved" />
          <el-option label="已驳回" value="rejected" />
        </el-select>
        <el-button @click="loadItems">刷新</el-button>
      </div>
    </div>

    <el-card>
      <el-table :data="items" v-loading="loading" border>
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column prop="title" label="作品名" min-width="220" />
        <el-table-column prop="author" label="作者" width="160" />
        <el-table-column prop="category_name" label="分类" width="120" />
        <el-table-column label="标签" min-width="180">
          <template #default="{ row }">
            <el-space wrap>
              <el-tag v-for="tag in row.tags || []" :key="tag.id" size="small">{{ tag.label }}</el-tag>
              <span v-if="!row.tags?.length">-</span>
            </el-space>
          </template>
        </el-table-column>
        <el-table-column label="审核状态" width="120">
          <template #default="{ row }">
            <el-tag :type="auditStatusTagType(row.audit_status)">{{ auditStatusLabel(row.audit_status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="上架状态" width="120">
          <template #default="{ row }">
            <el-tag :type="shelfStatusTagType(row.shelf_status)">{{ shelfStatusLabel(row.shelf_status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="audit_submitted_at" label="提审时间" width="180" />
        <el-table-column prop="updated_at" label="更新时间" width="180" />
        <el-table-column label="操作" width="240">
          <template #default="{ row }">
            <el-button link type="primary" @click="onView(row)">查看</el-button>
            <el-button link type="success" :disabled="row.audit_status !== 'pending'" @click="openReview(row, 'approve')">
              通过
            </el-button>
            <el-button link type="danger" :disabled="row.audit_status !== 'pending'" @click="openReview(row, 'reject')">
              驳回
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="reviewDialogVisible" :title="reviewAction === 'approve' ? '审核通过' : '审核驳回'" width="560px">
      <el-form :model="reviewForm" label-width="100px">
        <el-form-item label="审核意见">
          <el-input
            v-model="reviewForm.audit_comment"
            type="textarea"
            :rows="5"
            :placeholder="reviewAction === 'approve' ? '可选，给作者的通过说明' : '建议填写驳回原因与修改建议'"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="reviewDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="reviewLoading" @click="submitReview">确认</el-button>
      </template>
    </el-dialog>

    <el-drawer v-model="detailVisible" title="作品资料详情" size="50%">
      <div v-if="activeItem" class="detail">
        <h3>{{ activeItem.title }}</h3>
        <p><strong>作者：</strong>{{ activeItem.author || '-' }}</p>
        <p><strong>分类：</strong>{{ activeItem.category_name || '-' }}</p>
        <p><strong>副标题：</strong>{{ activeItem.subtitle || '-' }}</p>
        <p><strong>简介：</strong>{{ activeItem.description || '-' }}</p>
        <p><strong>审核状态：</strong>{{ auditStatusLabel(activeItem.audit_status) }}</p>
        <p><strong>审核意见：</strong>{{ activeItem.audit_comment || '-' }}</p>
        <p><strong>标签：</strong>{{ (activeItem.tags || []).map((item) => item.label).join(' / ') || '-' }}</p>
        <el-divider />
        <div class="detail-grid">
          <div><strong>连载状态：</strong>{{ completionStatusLabel(activeItem.completion_status) }}</div>
          <div><strong>收费模式：</strong>{{ priceTypeLabel(activeItem.price_type) }}</div>
          <div><strong>创作属性：</strong>{{ creationTypeLabel(activeItem.creation_type) }}</div>
          <div><strong>上架状态：</strong>{{ shelfStatusLabel(activeItem.shelf_status) }}</div>
        </div>
      </div>
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { getAdminWorkReviews, reviewAdminWork, type AdminWorkReviewItem } from '@/api/admin'

const loading = ref(false)
const reviewLoading = ref(false)
const items = ref<AdminWorkReviewItem[]>([])
const keyword = ref('')
const auditStatus = ref('')

const detailVisible = ref(false)
const activeItem = ref<AdminWorkReviewItem | null>(null)

const reviewDialogVisible = ref(false)
const reviewAction = ref<'approve' | 'reject'>('approve')
const reviewBookId = ref<number | null>(null)
const reviewForm = reactive({
  audit_comment: '',
})

const auditStatusLabel = (value?: string) => {
  if (value === 'pending') return '待审核'
  if (value === 'approved') return '已通过'
  if (value === 'rejected') return '已驳回'
  if (value === 'draft') return '草稿'
  return value || '-'
}

const auditStatusTagType = (value?: string) => {
  if (value === 'approved') return 'success'
  if (value === 'pending') return 'warning'
  if (value === 'rejected') return 'danger'
  return 'info'
}

const shelfStatusLabel = (value?: string) => {
  if (value === 'up') return '已上架'
  if (value === 'forced_down') return '强制下架'
  return '已下架'
}

const shelfStatusTagType = (value?: string) => {
  if (value === 'up') return 'success'
  if (value === 'forced_down') return 'danger'
  return 'info'
}

const completionStatusLabel = (value?: string) => {
  if (value === 'completed') return '已完结'
  if (value === 'paused') return '暂停'
  return '连载中'
}

const priceTypeLabel = (value?: string) => (value === 'paid' ? '付费' : '免费')
const creationTypeLabel = (value?: string) => {
  if (value === 'fanfic') return '同人'
  if (value === 'derivative') return '衍生'
  return '原创'
}

const loadItems = async () => {
  loading.value = true
  try {
    const res = await getAdminWorkReviews({
      keyword: keyword.value || undefined,
      audit_status: auditStatus.value || undefined,
    })
    items.value = res.items || []
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载作品审核列表失败')
  } finally {
    loading.value = false
  }
}

const onView = (row: AdminWorkReviewItem) => {
  activeItem.value = row
  detailVisible.value = true
}

const openReview = (row: AdminWorkReviewItem, action: 'approve' | 'reject') => {
  reviewBookId.value = row.id
  reviewAction.value = action
  reviewForm.audit_comment = ''
  reviewDialogVisible.value = true
}

const submitReview = async () => {
  if (!reviewBookId.value) return
  reviewLoading.value = true
  try {
    await reviewAdminWork(reviewBookId.value, {
      action: reviewAction.value,
      audit_comment: reviewForm.audit_comment || undefined,
    })
    ElMessage.success('审核完成')
    reviewDialogVisible.value = false
    await loadItems()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '审核失败')
  } finally {
    reviewLoading.value = false
  }
}

onMounted(loadItems)
</script>

<style scoped>
.admin-page {
  padding: 20px;
}

.toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  margin-bottom: 16px;
}

.actions {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}

.detail {
  font-size: 14px;
  line-height: 1.8;
}

.detail-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}
</style>
