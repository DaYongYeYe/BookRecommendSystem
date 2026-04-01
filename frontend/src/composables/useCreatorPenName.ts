import { reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { getUserProfile, updateUserProfile, type UserProfile } from '@/api/user'

export function useCreatorPenName() {
  const profile = ref<UserProfile | null>(null)
  const checking = ref(false)
  const saving = ref(false)
  const penNameDialogVisible = ref(false)
  const penNameForm = reactive({
    pen_name: '',
  })

  const hasPenName = () => !!penNameForm.pen_name.trim()

  async function loadCreatorProfile() {
    checking.value = true
    try {
      const res = await getUserProfile()
      profile.value = res.user
      penNameForm.pen_name = res.user.pen_name || ''
      penNameDialogVisible.value = !res.user.pen_name
    } catch (error: any) {
      ElMessage.error(error?.response?.data?.error || '创作者资料加载失败')
    } finally {
      checking.value = false
    }
  }

  async function savePenName() {
    const nextPenName = penNameForm.pen_name.trim()
    if (!nextPenName) {
      ElMessage.warning('请先填写笔名')
      return false
    }

    saving.value = true
    try {
      const res = await updateUserProfile({ pen_name: nextPenName })
      profile.value = res.user
      penNameForm.pen_name = res.user.pen_name || nextPenName
      penNameDialogVisible.value = false
      ElMessage.success('笔名已保存')
      return true
    } catch (error: any) {
      ElMessage.error(error?.response?.data?.error || '笔名保存失败')
      return false
    } finally {
      saving.value = false
    }
  }

  return {
    profile,
    checking,
    saving,
    penNameDialogVisible,
    penNameForm,
    hasPenName,
    loadCreatorProfile,
    savePenName,
  }
}
