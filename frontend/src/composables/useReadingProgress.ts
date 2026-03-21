import { Ref, nextTick, ref } from 'vue'
import { getToken } from '@/api/request'
import { getReadingProgress, saveReadingProgress } from '@/api/reader'

export function useReadingProgress(bookId: Ref<string>, activeSectionId: Ref<string>) {
  const lastProgressSyncAt = ref(0)

  async function resumeIfNeeded(shouldResume: boolean) {
    if (!getToken() || !shouldResume) {
      return
    }

    try {
      const response = await getReadingProgress(bookId.value)
      if (!response.has_progress || !response.progress?.section_id) {
        return
      }

      activeSectionId.value = response.progress.section_id
      await nextTick()
      document.getElementById(response.progress.section_id)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    } catch (_error) {
      // Keep silent and continue reading from beginning.
    }
  }

  function getScrollPercent() {
    const doc = document.documentElement
    const maxScroll = doc.scrollHeight - doc.clientHeight
    if (maxScroll <= 0) {
      return 0
    }
    return Math.min(100, Math.max(0, (doc.scrollTop / maxScroll) * 100))
  }

  async function syncReadingProgress(force = false) {
    if (!getToken() || !activeSectionId.value) {
      return
    }

    const now = Date.now()
    if (!force && now - lastProgressSyncAt.value < 3000) {
      return
    }
    lastProgressSyncAt.value = now

    try {
      await saveReadingProgress(bookId.value, {
        section_id: activeSectionId.value,
        scroll_percent: getScrollPercent(),
      })
    } catch (_error) {
      // Keep reading even if sync fails.
    }
  }

  return {
    resumeIfNeeded,
    syncReadingProgress,
  }
}
