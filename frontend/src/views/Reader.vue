<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { useRoute, useRouter } from 'vue-router'
import {
  addBookToShelf,
  createBookComment,
  createHighlight,
  createHighlightComment,
  createReaderBookmark,
  deleteReaderBookmark,
  getReader,
  getReaderPreferences,
  getReaderSections,
  reactHighlight,
  saveReaderPreferences,
  type ReaderBookmark,
  type ReaderHighlight,
  type ReaderPayload,
  type ReaderSectionsPagination,
} from '@/api/reader'
import { getToken } from '@/api/request'
import { getUserFavorites } from '@/api/user'
import { useReaderPreferences, type ReaderMargin, type ReaderTheme } from '@/composables/useReaderPreferences'
import { useReadingProgress } from '@/composables/useReadingProgress'

type CommentDraft = {
  paragraphId: string
  sectionId: string
  selectedText: string
  startOffset: number
  endOffset: number
}

type PanelType = 'none' | 'catalog' | 'settings' | 'comments' | 'bookmarks'

const route = useRoute()
const router = useRouter()
const bookId = computed(() => String(route.params.bookId || '1'))

const reader = ref<ReaderPayload | null>(null)
const loading = ref(false)
const loadingMoreSections = ref(false)
const sectionPagination = ref<ReaderSectionsPagination | null>(null)
const addingToShelf = ref(false)
const isInShelf = ref(false)
const activeSectionId = ref('')
const activeParagraphId = ref('')
const activePanel = ref<PanelType>('none')
const commentDraft = ref<CommentDraft | null>(null)
const commentDraftContent = ref('')
const replyDrafts = ref<Record<number, string>>({})
const reactingHighlightIds = ref<Set<number>>(new Set())
const bookCommentDraft = ref('')
const bookmarks = ref<ReaderBookmark[]>([])
const bookmarkNoteDraft = ref('')
const showTopChrome = ref(true)
const preferenceLoaded = ref(false)
const postReadSectionId = 'reader-post-read'
const speechSupported = typeof window !== 'undefined' && 'speechSynthesis' in window
const isSpeaking = ref(false)
const isSpeechPaused = ref(false)
const speechStatus = ref('')
const speechRunId = ref(0)
let selectionCaptureTimer: ReturnType<typeof window.setTimeout> | null = null

const { readerTheme, readerFontSize, readerLineHeight, readerMargin, setTheme, setFontSize, setLineHeight, setMargin } =
  useReaderPreferences()
const { resumeIfNeeded, syncReadingProgress, getAnalyticsContext } = useReadingProgress(
  bookId,
  activeSectionId,
  activeParagraphId
)

const themeStyles: Record<
  ReaderTheme,
  {
    root: string
    page: string
    text: string
    textSecondary: string
    textMuted: string
    border: string
    panel: string
    subtle: string
  }
> = {
  light: {
    root: 'min-h-screen bg-stone-100 text-stone-900',
    page: 'bg-white',
    text: 'text-stone-900',
    textSecondary: 'text-stone-600',
    textMuted: 'text-stone-400',
    border: 'border-stone-200',
    panel: 'border-stone-200 bg-white text-stone-900',
    subtle: 'bg-stone-100',
  },
  dark: {
    root: 'min-h-screen bg-[#111418] text-[#d8d3ca]',
    page: 'bg-[#171b20]',
    text: 'text-[#d8d3ca]',
    textSecondary: 'text-[#aaa49a]',
    textMuted: 'text-[#79736c]',
    border: 'border-white/10',
    panel: 'border-white/10 bg-[#20252b] text-[#d8d3ca]',
    subtle: 'bg-white/10',
  },
  green: {
    root: 'min-h-screen bg-[#dfead8] text-[#293525]',
    page: 'bg-[#edf5e8]',
    text: 'text-[#293525]',
    textSecondary: 'text-[#4d5f45]',
    textMuted: 'text-[#718168]',
    border: 'border-[#c8d8bf]',
    panel: 'border-[#c8d8bf] bg-[#f3faef] text-[#293525]',
    subtle: 'bg-[#d6e5ce]',
  },
  parchment: {
    root: 'min-h-screen bg-[#efe1c5] text-[#3b2e20]',
    page: 'bg-[#f8edcf]',
    text: 'text-[#3b2e20]',
    textSecondary: 'text-[#685744]',
    textMuted: 'text-[#8b7964]',
    border: 'border-[#dfcfac]',
    panel: 'border-[#dfcfac] bg-[#fff4d8] text-[#3b2e20]',
    subtle: 'bg-[#eadbb9]',
  },
}

const ts = computed(() => themeStyles[readerTheme.value] || themeStyles.light)

const contentWidthClass = computed(() => {
  if (readerMargin.value === 'narrow') return 'max-w-[680px]'
  if (readerMargin.value === 'wide') return 'max-w-[980px]'
  return 'max-w-[780px]'
})

const currentSectionIndex = computed(() => {
  if (!reader.value) return 0
  return Math.max(
    reader.value.outline.findIndex((section) => section.id === activeSectionId.value),
    0
  )
})

const currentSectionTitle = computed(() => reader.value?.outline[currentSectionIndex.value]?.title || '')
const hasPrevChapter = computed(() => currentSectionIndex.value > 0)
const hasNextChapter = computed(() => (reader.value ? currentSectionIndex.value < reader.value.outline.length - 1 : false))
const loadedSectionCount = computed(() => reader.value?.sections.length || 0)

const progressPercent = computed(() => {
  if (!reader.value) return 0
  const total = reader.value.outline.length || reader.value.sections.length || 1
  return Math.min(100, Math.round(((currentSectionIndex.value + 1) / total) * 100))
})

const currentBookmark = computed(() => bookmarks.value.find((item) => item.section_id === activeSectionId.value) || null)

const sectionTitleById = computed(() => {
  const map: Record<string, string> = {}
  reader.value?.outline.forEach((section) => {
    map[section.id] = section.title
  })
  return map
})

const paragraphCommentMap = computed(() => {
  const map: Record<string, ReaderHighlight[]> = {}
  ;(reader.value?.highlights || []).forEach((item) => {
    if (!map[item.paragraph_id]) map[item.paragraph_id] = []
    map[item.paragraph_id].push(item)
  })
  return map
})

const activeParagraphMeta = computed(() => (activeParagraphId.value ? getParagraphMeta(activeParagraphId.value) : null))
const activeParagraphComments = computed(() => {
  if (!activeParagraphId.value) return []
  return paragraphCommentMap.value[activeParagraphId.value] || []
})
const otherParagraphComments = computed(() => activeParagraphComments.value.filter((item) => !item.is_mine))
const myParagraphComments = computed(() => activeParagraphComments.value.filter((item) => item.is_mine))
const orderedParagraphComments = computed(() => [...otherParagraphComments.value, ...myParagraphComments.value])
const activeParagraphCommentCount = computed(() => activeParagraphComments.value.length)
const hasMyParagraphComment = computed(() => myParagraphComments.value.length > 0)
const highlightedBookComments = computed(() => (reader.value?.book_comments || []).slice(0, 4))

const currentSectionText = computed(() => {
  if (!reader.value) return ''
  const section = reader.value.sections.find((item) => item.id === activeSectionId.value)
  if (!section) return ''
  return [section.title, ...section.paragraphs.map((paragraph) => paragraph.text)].join('\n').trim()
})

const estimatedMinutesLeft = computed(() => {
  const totalWords = reader.value?.book.total_words || reader.value?.book.word_count || 0
  if (!totalWords) return 0
  return Math.max(1, Math.round((totalWords * (1 - progressPercent.value / 100)) / 400))
})

const relatedSections = computed(() => {
  if (reader.value?.related_sections?.length) {
    return reader.value.related_sections.filter((section) => section.items.length > 0)
  }
  if (reader.value?.related_books?.length) {
    return [
      {
        key: 'related',
        title: '读完这本还可以看',
        description: '同题材、同热度和相近口味的作品。',
        items: reader.value.related_books,
      },
    ]
  }
  return []
})

async function loadReader() {
  loading.value = true
  try {
    const payload = await getReader(bookId.value, getAnalyticsContext())
    reader.value = payload
    sectionPagination.value = payload.sections_pagination || null
    bookmarks.value = payload.bookmarks || []
    activeSectionId.value = payload.sections[0]?.id || ''
    loading.value = false
    await nextTick()
    if (typeof route.query.section === 'string') {
      await scrollToSection(route.query.section)
    }
    await resumeIfNeeded(route.query.resume === '1', async (target) => {
      await loadMoreReaderSections(target.sectionId)
      await nextTick()
      return true
    })
    if (route.query.listen === '1') {
      window.setTimeout(startListening, 300)
    }
  } catch (_error) {
    ElMessage.error('阅读内容加载失败，请稍后重试')
  } finally {
    loading.value = false
  }
}

async function loadShelfState() {
  if (!getToken()) {
    isInShelf.value = false
    return
  }
  try {
    const favorites = await getUserFavorites()
    isInShelf.value = favorites.items.some((item) => item.id === Number(bookId.value))
  } catch (_error) {
    isInShelf.value = false
  }
}

async function loadReaderPreferences() {
  try {
    const data = await getReaderPreferences()
    setTheme(data.theme === 'dark' ? 'dark' : data.theme === 'green' ? 'green' : data.theme === 'parchment' ? 'parchment' : 'light')
    setFontSize(Number(data.font_size) || 20)
    setLineHeight(Number(data.line_height) || 1.9)
    setMargin((data.margin as ReaderMargin) || 'medium')
  } catch (_error) {
    // Local defaults are good enough when the reader preference endpoint is unavailable.
  } finally {
    preferenceLoaded.value = true
  }
}

async function persistReaderPreferences() {
  if (!preferenceLoaded.value || !getToken()) return
  try {
    await saveReaderPreferences({
      theme: readerTheme.value,
      font_size: readerFontSize.value,
      line_height: readerLineHeight.value,
      margin: readerMargin.value,
      show_highlights: false,
      show_comments: true,
    })
  } catch (_error) {
    // Preference sync should never block reading.
  }
}

function focusActiveParagraphForComments() {
  if (!reader.value) return
  if (activeParagraphId.value && getParagraphMeta(activeParagraphId.value)) {
    if (!hasMyCommentForParagraph(activeParagraphId.value) && !commentDraft.value) {
      const meta = getParagraphMeta(activeParagraphId.value)
      if (meta) {
        commentDraft.value = {
          paragraphId: activeParagraphId.value,
          sectionId: meta.section.id,
          selectedText: meta.paragraph.text,
          startOffset: 0,
          endOffset: meta.paragraph.text.length,
        }
      }
    }
    return
  }

  const currentSection = reader.value.sections.find((section) => section.id === activeSectionId.value)
  const fallbackParagraph = currentSection?.paragraphs[0] || reader.value.sections[0]?.paragraphs[0]
  if (fallbackParagraph) {
    activeParagraphId.value = fallbackParagraph.id
    if (!hasMyCommentForParagraph(fallbackParagraph.id)) {
      const meta = getParagraphMeta(fallbackParagraph.id)
      if (meta) {
        commentDraft.value = {
          paragraphId: fallbackParagraph.id,
          sectionId: meta.section.id,
          selectedText: meta.paragraph.text,
          startOffset: 0,
          endOffset: meta.paragraph.text.length,
        }
      }
    }
  }
}

function hasMyCommentForParagraph(paragraphId: string) {
  return (paragraphCommentMap.value[paragraphId] || []).some((item) => item.is_mine)
}

function updateHighlight(updated: ReaderHighlight) {
  if (!reader.value) return
  const index = reader.value.highlights.findIndex((item) => item.id === updated.id)
  if (index === -1) return
  reader.value.highlights[index] = {
    ...reader.value.highlights[index],
    ...updated,
    comments: updated.comments?.length ? updated.comments : reader.value.highlights[index].comments,
  }
}

function togglePanel(panel: PanelType) {
  if (panel === 'comments') focusActiveParagraphForComments()
  activePanel.value = activePanel.value === panel ? 'none' : panel
  showTopChrome.value = true
}

function closePanel() {
  activePanel.value = 'none'
}

function toggleChrome() {
  if (activePanel.value !== 'none') {
    closePanel()
    return
  }
  showTopChrome.value = !showTopChrome.value
}

async function scrollToSection(sectionId: string) {
  await loadMoreReaderSections(sectionId)
  activeSectionId.value = sectionId
  await nextTick()
  document.getElementById(sectionId)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  closePanel()
  return true
}

function scrollToPostRead() {
  document.getElementById(postReadSectionId)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
}

async function goToPrevChapter() {
  if (!hasPrevChapter.value || !reader.value) return false
  const prev = reader.value.outline[currentSectionIndex.value - 1]
  return prev ? scrollToSection(prev.id) : false
}

async function goToNextChapter() {
  if (!reader.value) return false
  if (!hasNextChapter.value) {
    scrollToPostRead()
    return false
  }
  const next = reader.value.outline[currentSectionIndex.value + 1]
  return next ? scrollToSection(next.id) : false
}

async function loadMoreReaderSections(targetSectionId?: string) {
  if (!reader.value || loadingMoreSections.value) return false
  if (targetSectionId && reader.value.sections.some((section) => section.id === targetSectionId)) return true

  let pagination = sectionPagination.value
  let loadedTarget = false
  while (pagination?.has_more) {
    loadingMoreSections.value = true
    try {
      const nextOffset = pagination.next_offset ?? reader.value.sections.length
      const payload = await getReaderSections(bookId.value, nextOffset, 5)
      const existingIds = new Set(reader.value.sections.map((section) => section.id))
      reader.value.sections.push(...payload.sections.filter((section) => !existingIds.has(section.id)))
      sectionPagination.value = payload.pagination
      pagination = payload.pagination
      if (!targetSectionId || reader.value.sections.some((section) => section.id === targetSectionId)) {
        loadedTarget = true
        break
      }
    } catch (_error) {
      ElMessage.error('后续章节加载失败，请稍后重试')
      break
    } finally {
      loadingMoreSections.value = false
    }
  }
  return loadedTarget || !targetSectionId || reader.value.sections.some((section) => section.id === targetSectionId)
}

function getParagraphMeta(paragraphId: string) {
  if (!reader.value) return null
  for (const section of reader.value.sections) {
    const paragraph = section.paragraphs.find((item) => item.id === paragraphId)
    if (paragraph) return { section, paragraph }
  }
  return null
}

function openParagraphComment(paragraphId: string) {
  const meta = getParagraphMeta(paragraphId)
  if (!meta) return
  activeSectionId.value = meta.section.id
  activeParagraphId.value = paragraphId
  if (hasMyCommentForParagraph(paragraphId)) {
    clearCommentDraft()
    activePanel.value = 'comments'
    showTopChrome.value = true
    return
  }
  commentDraft.value = {
    paragraphId,
    sectionId: meta.section.id,
    selectedText: meta.paragraph.text,
    startOffset: 0,
    endOffset: meta.paragraph.text.length,
  }
  commentDraftContent.value = ''
  activePanel.value = 'comments'
  showTopChrome.value = true
}

function captureSelectionComment() {
  const selection = window.getSelection()
  if (!selection || selection.rangeCount === 0 || selection.isCollapsed) return

  const range = selection.getRangeAt(0)
  const startParagraph = (range.startContainer.nodeType === Node.TEXT_NODE
    ? range.startContainer.parentElement
    : (range.startContainer as Element)
  )?.closest?.('[data-paragraph-id]') as HTMLElement | null
  const endParagraph = (range.endContainer.nodeType === Node.TEXT_NODE
    ? range.endContainer.parentElement
    : (range.endContainer as Element)
  )?.closest?.('[data-paragraph-id]') as HTMLElement | null

  if (!startParagraph || !endParagraph || startParagraph !== endParagraph) return
  const paragraphId = startParagraph.dataset.paragraphId
  const meta = paragraphId ? getParagraphMeta(paragraphId) : null
  if (!paragraphId || !meta) return

  const selectedText = range.toString().trim()
  if (!selectedText) return
  const preSelectionRange = range.cloneRange()
  preSelectionRange.selectNodeContents(startParagraph)
  preSelectionRange.setEnd(range.startContainer, range.startOffset)
  const startOffset = preSelectionRange.toString().length

  commentDraft.value = {
    paragraphId,
    sectionId: meta.section.id,
    selectedText,
    startOffset,
    endOffset: startOffset + selectedText.length,
  }
  commentDraftContent.value = ''
  activeSectionId.value = meta.section.id
  activeParagraphId.value = paragraphId
  if (hasMyCommentForParagraph(paragraphId)) {
    clearCommentDraft()
    activePanel.value = 'comments'
    showTopChrome.value = true
    return
  }
  activePanel.value = 'comments'
  showTopChrome.value = true
}

function scheduleSelectionCapture() {
  if (selectionCaptureTimer) window.clearTimeout(selectionCaptureTimer)
  selectionCaptureTimer = window.setTimeout(() => {
    selectionCaptureTimer = null
    captureSelectionComment()
  }, 180)
}

function clearCommentDraft() {
  commentDraft.value = null
  commentDraftContent.value = ''
  window.getSelection()?.removeAllRanges()
}

async function submitParagraphComment() {
  if (!commentDraft.value || !reader.value || !commentDraftContent.value.trim()) return
  if (hasMyCommentForParagraph(commentDraft.value.paragraphId)) {
    ElMessage.info('你已经评论过这一段了，可以先看看并点赞其他人的评论')
    clearCommentDraft()
    return
  }
  try {
    const response = await createHighlight(bookId.value, {
      paragraph_id: commentDraft.value.paragraphId,
      start_offset: commentDraft.value.startOffset,
      end_offset: commentDraft.value.endOffset,
      selected_text: commentDraft.value.selectedText,
      note: commentDraftContent.value.trim(),
      color: 'comment',
    })
    reader.value.highlights.unshift(response.highlight)
    activeParagraphId.value = response.highlight.paragraph_id
    clearCommentDraft()
    activePanel.value = 'comments'
    ElMessage.success('评论已发布')
  } catch (_error) {
    ElMessage.error('评论发布失败，请先登录后再试')
  }
}

async function toggleHighlightReaction(item: ReaderHighlight) {
  if (item.is_mine || !hasMyParagraphComment.value || reactingHighlightIds.value.has(item.id)) return
  reactingHighlightIds.value = new Set([...reactingHighlightIds.value, item.id])
  try {
    const response = await reactHighlight(bookId.value, item.id, !item.liked_by_me)
    updateHighlight(response.highlight)
  } catch (_error) {
    ElMessage.error('点赞失败，请先发表本段评论后再试')
  } finally {
    const next = new Set(reactingHighlightIds.value)
    next.delete(item.id)
    reactingHighlightIds.value = next
  }
}

async function submitCommentReply(item: ReaderHighlight) {
  const content = replyDrafts.value[item.id]?.trim()
  if (!content) return
  try {
    const response = await createHighlightComment(bookId.value, item.id, { content })
    item.comments.push(response.comment)
    replyDrafts.value[item.id] = ''
    ElMessage.success('回复已发布')
  } catch (_error) {
    ElMessage.error('回复失败，请先登录后再试')
  }
}

async function submitBookComment() {
  if (!bookCommentDraft.value.trim() || !reader.value) return
  try {
    const response = await createBookComment(bookId.value, { content: bookCommentDraft.value.trim() })
    reader.value.book_comments.unshift(response.comment)
    bookCommentDraft.value = ''
    ElMessage.success('书评发布成功')
  } catch (_error) {
    ElMessage.error('书评发布失败，请先登录后再试')
  }
}

async function saveBookmark() {
  if (!reader.value || !activeSectionId.value) return
  try {
    const response = await createReaderBookmark(bookId.value, {
      section_id: activeSectionId.value,
      paragraph_id: activeParagraphId.value || null,
      note: bookmarkNoteDraft.value || currentSectionTitle.value,
    })
    bookmarks.value = [response.bookmark, ...bookmarks.value.filter((item) => item.id !== response.bookmark.id)]
    bookmarkNoteDraft.value = ''
    activePanel.value = 'bookmarks'
    ElMessage.success('书签已保存')
  } catch (_error) {
    ElMessage.error('书签保存失败，请先登录后再试')
  }
}

async function removeBookmark(bookmarkId: number) {
  try {
    await deleteReaderBookmark(bookId.value, bookmarkId)
    bookmarks.value = bookmarks.value.filter((item) => item.id !== bookmarkId)
    ElMessage.success('书签已删除')
  } catch (_error) {
    ElMessage.error('书签删除失败')
  }
}

async function handleAddToShelf() {
  if (isInShelf.value) return
  addingToShelf.value = true
  try {
    await addBookToShelf(bookId.value)
    isInShelf.value = true
    ElMessage.success('已加入书架')
  } catch (_error) {
    ElMessage.error('加入书架失败，请先登录')
  } finally {
    addingToShelf.value = false
  }
}

function stopListening() {
  if (!speechSupported) return
  speechRunId.value += 1
  window.speechSynthesis.cancel()
  isSpeaking.value = false
  isSpeechPaused.value = false
  speechStatus.value = ''
}

function startListening() {
  if (!speechSupported) {
    ElMessage.warning('当前浏览器不支持语音朗读')
    return
  }
  if (!currentSectionText.value) {
    ElMessage.warning('当前章节暂无可朗读内容')
    return
  }
  speechRunId.value += 1
  const runId = speechRunId.value
  window.speechSynthesis.cancel()
  const utterance = new SpeechSynthesisUtterance(currentSectionText.value)
  utterance.lang = 'zh-CN'
  utterance.rate = 0.95
  utterance.pitch = 1
  utterance.onstart = () => {
    isSpeaking.value = true
    isSpeechPaused.value = false
    speechStatus.value = `正在朗读：${currentSectionTitle.value || '当前章节'}`
  }
  utterance.onend = () => {
    if (runId !== speechRunId.value) return
    isSpeaking.value = false
    isSpeechPaused.value = false
    speechStatus.value = hasNextChapter.value ? '本章朗读完成' : '已读到最后一章'
  }
  utterance.onerror = () => {
    if (runId !== speechRunId.value) return
    isSpeaking.value = false
    isSpeechPaused.value = false
    speechStatus.value = '朗读中断，请稍后重试'
  }
  window.speechSynthesis.speak(utterance)
}

function toggleListening() {
  if (!speechSupported) {
    ElMessage.warning('当前浏览器不支持语音朗读')
    return
  }
  if (!isSpeaking.value) {
    startListening()
    return
  }
  if (isSpeechPaused.value) {
    window.speechSynthesis.resume()
    isSpeechPaused.value = false
    speechStatus.value = `正在朗读：${currentSectionTitle.value || '当前章节'}`
  } else {
    window.speechSynthesis.pause()
    isSpeechPaused.value = true
    speechStatus.value = '朗读已暂停'
  }
}

function formatCount(value?: number | null) {
  const num = Number(value || 0)
  if (num >= 10000) return `${(num / 10000).toFixed(1)}万`
  return String(num)
}

function formatWordCount(value?: number | null) {
  const num = Number(value || 0)
  if (!num) return '未标注'
  if (num >= 10000) return `${(num / 10000).toFixed(1)}万字`
  return `${num}字`
}

function goBook(targetBookId: number) {
  router.push(`/books/${targetBookId}`)
}

function handleScroll() {
  if (!reader.value) return
  let currentSection = reader.value.sections[0]?.id || ''
  let currentParagraph = ''
  reader.value.sections.forEach((section) => {
    const element = document.getElementById(section.id)
    if (element && element.getBoundingClientRect().top <= 120) currentSection = section.id
  })
  document.querySelectorAll<HTMLElement>('[data-paragraph-id]').forEach((paragraph) => {
    if (paragraph.getBoundingClientRect().top <= 180) currentParagraph = paragraph.dataset.paragraphId || ''
  })
  activeSectionId.value = currentSection
  activeParagraphId.value = currentParagraph
  const doc = document.documentElement
  if (sectionPagination.value?.has_more && doc.scrollHeight - (doc.scrollTop + doc.clientHeight) < 900) {
    void loadMoreReaderSections()
  }
  syncReadingProgress(false)
}

function handleKeydown(e: KeyboardEvent) {
  if (e.key === 'ArrowLeft') void goToPrevChapter()
  if (e.key === 'ArrowRight') void goToNextChapter()
  if (e.key === 'Escape') closePanel()
}

onMounted(async () => {
  await loadReaderPreferences()
  await loadShelfState()
  await loadReader()
  window.addEventListener('scroll', handleScroll, { passive: true })
  document.addEventListener('mouseup', captureSelectionComment)
  document.addEventListener('touchend', scheduleSelectionCapture, { passive: true })
  document.addEventListener('selectionchange', scheduleSelectionCapture)
  document.addEventListener('keydown', handleKeydown)
})

onBeforeUnmount(() => {
  syncReadingProgress(true)
  stopListening()
  if (selectionCaptureTimer) window.clearTimeout(selectionCaptureTimer)
  window.removeEventListener('scroll', handleScroll)
  document.removeEventListener('mouseup', captureSelectionComment)
  document.removeEventListener('touchend', scheduleSelectionCapture)
  document.removeEventListener('selectionchange', scheduleSelectionCapture)
  document.removeEventListener('keydown', handleKeydown)
})

watch(
  () => route.params.bookId,
  async () => {
    stopListening()
    clearCommentDraft()
    closePanel()
    bookmarks.value = []
    sectionPagination.value = null
    await nextTick()
    await loadShelfState()
    await loadReader()
  }
)

watch([readerTheme, readerFontSize, readerLineHeight, readerMargin], () => {
  void persistReaderPreferences()
})
</script>

<template>
  <div :class="[ts.root, 'pb-24']">
    <header
      v-if="reader && showTopChrome"
      class="fixed inset-x-0 top-0 z-40 border-b px-4 py-3 backdrop-blur-xl transition md:px-8"
      :class="[ts.panel, ts.border]"
    >
      <div class="mx-auto flex max-w-3xl items-center gap-3">
        <button class="rounded-full px-2 py-1 text-xl leading-none" :class="ts.text" @click="router.push(`/books/${bookId}`)">‹</button>
        <div class="min-w-0 flex-1 text-center">
          <p class="truncate text-sm font-semibold">{{ reader.book.title }}</p>
          <p class="mt-0.5 truncate text-xs" :class="ts.textMuted">{{ currentSectionTitle || reader.book.author }}</p>
        </div>
        <button class="rounded-full px-2 py-1 text-sm" :class="ts.textSecondary" @click="togglePanel('catalog')">
          目录
        </button>
      </div>
    </header>

    <main class="mx-auto px-0 pt-0 md:px-6" :class="contentWidthClass">
      <div v-if="loading" class="mx-4 mt-8 rounded-2xl p-8 text-center" :class="[ts.page, ts.textMuted]">
        正在加载正文...
      </div>

      <template v-else-if="reader">
        <article
          class="min-h-screen px-5 pb-10 pt-12 shadow-sm md:mt-6 md:rounded-2xl md:px-10 md:pt-16"
          :class="ts.page"
          @click.self="toggleChrome"
        >
          <section
            v-for="(section, sectionIdx) in reader.sections"
            :id="section.id"
            :key="section.id"
            class="scroll-mt-20 border-b py-8 last:border-b-0"
            :class="ts.border"
          >
            <p class="text-center text-xs" :class="ts.textMuted">第 {{ sectionIdx + 1 }} 章</p>
            <h1 class="mt-3 text-center text-2xl font-semibold leading-snug" :class="ts.text">{{ section.title }}</h1>
            <p v-if="section.summary" class="mx-auto mt-4 max-w-xl text-center text-sm leading-7" :class="ts.textSecondary">
              {{ section.summary }}
            </p>

            <div class="mt-8 space-y-4">
              <div
                v-for="paragraph in section.paragraphs"
                :key="paragraph.id"
                :data-paragraph-id="paragraph.id"
                class="group relative rounded-lg px-1 py-1"
                :class="activeParagraphId === paragraph.id ? ts.subtle : ''"
              >
                <p
                  class="whitespace-pre-wrap text-justify transition"
                  :class="ts.text"
                  :style="{ fontSize: `${readerFontSize}px`, lineHeight: String(readerLineHeight) }"
                  @click.stop="toggleChrome"
                >
                  {{ paragraph.text }}
                </p>
                <button
                  class="mt-2 rounded-full px-3 py-1 text-xs opacity-80 transition active:scale-95 md:opacity-0 md:group-hover:opacity-100"
                  :class="[ts.subtle, ts.textSecondary]"
                  @click.stop="openParagraphComment(paragraph.id)"
                >
                  评 {{ paragraphCommentMap[paragraph.id]?.length || '' }}
                </button>
              </div>
            </div>
          </section>

          <div v-if="sectionPagination?.has_more || loadingMoreSections" class="mt-6 flex justify-center">
            <button
              class="rounded-full border px-5 py-3 text-sm font-medium disabled:opacity-50"
              :class="[ts.border, ts.text]"
              :disabled="loadingMoreSections"
              @click="loadMoreReaderSections()"
            >
              {{ loadingMoreSections ? '正在加载后续章节...' : `继续加载 ${loadedSectionCount} / ${reader.outline.length}` }}
            </button>
          </div>

          <div class="mt-8 flex items-center justify-between gap-3">
            <button
              class="rounded-full border px-5 py-3 text-sm disabled:opacity-40"
              :class="[ts.border, ts.text]"
              :disabled="!hasPrevChapter"
              @click="goToPrevChapter"
            >
              上一章
            </button>
            <span class="text-xs" :class="ts.textMuted">{{ currentSectionIndex + 1 }} / {{ reader.outline.length }}</span>
            <button class="rounded-full border px-5 py-3 text-sm" :class="[ts.border, ts.text]" @click="goToNextChapter">
              {{ hasNextChapter ? '下一章' : '读完了' }}
            </button>
          </div>
        </article>

        <section :id="postReadSectionId" class="mx-4 mt-5 rounded-2xl p-5 md:mx-0" :class="[ts.page, ts.text]">
          <p class="text-xs" :class="ts.textMuted">读完之后</p>
          <h2 class="mt-2 text-xl font-semibold">留下书评，或者继续发现下一本</h2>
          <textarea
            v-model="bookCommentDraft"
            class="mt-4 min-h-24 w-full rounded-2xl border bg-transparent px-4 py-3 text-sm outline-none focus:border-orange-400"
            :class="ts.border"
            placeholder="写下你读完这本书后的感受..."
          />
          <div class="mt-3 flex gap-3">
            <button class="rounded-full bg-[#ff5a2a] px-5 py-2.5 text-sm font-medium text-white" @click="submitBookComment">
              发布书评
            </button>
            <button class="rounded-full border px-5 py-2.5 text-sm" :class="[ts.border, ts.text]" @click="router.push(`/books/${bookId}`)">
              返回详情
            </button>
          </div>

          <div v-if="relatedSections.length" class="mt-6 space-y-4">
            <section v-for="section in relatedSections" :key="section.key">
              <h3 class="text-base font-semibold">{{ section.title }}</h3>
              <div class="mt-3 flex gap-3 overflow-x-auto pb-2">
                <button
                  v-for="item in section.items"
                  :key="`${section.key}-${item.id}`"
                  class="w-28 shrink-0 text-left"
                  @click="goBook(item.id)"
                >
                  <img :src="item.cover || ''" :alt="item.title" class="h-36 w-24 rounded-md object-cover shadow" />
                  <span class="mt-2 block line-clamp-2 text-sm font-medium">{{ item.title }}</span>
                  <span class="mt-1 block truncate text-xs" :class="ts.textMuted">{{ item.author || '作者待补充' }}</span>
                </button>
              </div>
            </section>
          </div>
        </section>
      </template>
    </main>

    <nav
      v-if="reader && showTopChrome"
      class="fixed inset-x-0 bottom-0 z-40 border-t px-3 pb-[max(0.75rem,env(safe-area-inset-bottom))] pt-2 backdrop-blur-xl md:left-1/2 md:right-auto md:w-[420px] md:-translate-x-1/2 md:rounded-t-2xl md:border"
      :class="[ts.panel, ts.border]"
    >
      <div class="mx-auto flex max-w-md items-center justify-between">
        <button class="grid min-w-12 gap-1 text-center text-xs" :class="activePanel === 'catalog' ? 'text-[#ff5a2a]' : ts.textSecondary" @click="togglePanel('catalog')">
          <span class="text-lg">☰</span>
          <span>目录</span>
        </button>
        <button class="grid min-w-12 gap-1 text-center text-xs" :class="activePanel === 'settings' ? 'text-[#ff5a2a]' : ts.textSecondary" @click="togglePanel('settings')">
          <span class="text-lg">Aa</span>
          <span>设置</span>
        </button>
        <button class="grid min-w-12 gap-1 text-center text-xs" :class="activePanel === 'comments' ? 'text-[#ff5a2a]' : ts.textSecondary" @click="togglePanel('comments')">
          <span class="text-lg">评</span>
          <span>评论</span>
        </button>
        <button class="grid min-w-12 gap-1 text-center text-xs" :class="activePanel === 'bookmarks' ? 'text-[#ff5a2a]' : ts.textSecondary" @click="togglePanel('bookmarks')">
          <span class="text-lg">☆</span>
          <span>书签</span>
        </button>
        <button class="grid min-w-12 gap-1 text-center text-xs" :class="isSpeaking ? 'text-[#ff5a2a]' : ts.textSecondary" @click="toggleListening">
          <span class="text-lg">♫</span>
          <span>{{ isSpeaking && !isSpeechPaused ? '暂停' : '听书' }}</span>
        </button>
      </div>
      <div class="mt-2 h-1 overflow-hidden rounded-full" :class="ts.subtle">
        <div class="h-full rounded-full bg-[#ff5a2a]" :style="{ width: `${progressPercent}%` }" />
      </div>
      <p v-if="speechStatus" class="mt-2 text-center text-xs text-[#ff5a2a]">{{ speechStatus }}</p>
    </nav>

    <div v-if="activePanel !== 'none' && reader" class="fixed inset-0 z-50 bg-black/30" @click="closePanel">
      <section
        class="absolute inset-x-0 bottom-0 max-h-[78vh] overflow-hidden rounded-t-3xl border p-5 shadow-2xl md:left-1/2 md:right-auto md:w-[420px] md:-translate-x-1/2"
        :class="[ts.panel, ts.border]"
        @click.stop
      >
        <div class="mx-auto mb-4 h-1 w-10 rounded-full" :class="ts.subtle" />

        <template v-if="activePanel === 'catalog'">
          <div class="mb-4 flex items-center justify-between">
            <div>
              <h3 class="text-lg font-semibold">目录</h3>
              <p class="mt-1 text-xs" :class="ts.textMuted">共 {{ reader.outline.length }} 章，当前 {{ currentSectionIndex + 1 }} 章</p>
            </div>
            <span class="text-sm text-[#ff5a2a]">{{ progressPercent }}%</span>
          </div>
          <div class="max-h-[58vh] overflow-y-auto pr-1">
            <button
              v-for="(item, index) in reader.outline"
              :key="item.id"
              class="flex w-full items-center gap-3 border-b py-4 text-left text-sm"
              :class="[ts.border, activeSectionId === item.id ? 'text-[#ff5a2a]' : ts.text]"
              @click="scrollToSection(item.id)"
            >
              <span class="w-8 shrink-0 text-xs" :class="ts.textMuted">{{ index + 1 }}</span>
              <span class="min-w-0 flex-1 truncate" :class="item.level === 2 ? 'pl-4' : ''">{{ item.title }}</span>
              <span v-if="activeSectionId === item.id" class="text-xs">阅读中</span>
            </button>
          </div>
        </template>

        <template v-else-if="activePanel === 'settings'">
          <h3 class="text-lg font-semibold">阅读设置</h3>
        <div class="mt-5 space-y-6">
            <div>
              <p class="mb-3 text-sm font-medium">背景</p>
              <div class="grid grid-cols-4 gap-2">
                <button
                  v-for="opt in [
                    { key: 'light', label: '默认', cls: 'bg-white' },
                    { key: 'green', label: '护眼', cls: 'bg-[#edf5e8]' },
                    { key: 'parchment', label: '羊皮', cls: 'bg-[#f8edcf]' },
                    { key: 'dark', label: '夜间', cls: 'bg-[#171b20] text-white' },
                  ]"
                  :key="opt.key"
                  class="rounded-2xl border px-2 py-3 text-xs"
                  :class="[opt.cls, readerTheme === opt.key ? 'border-[#ff5a2a]' : ts.border]"
                  @click="setTheme(opt.key as ReaderTheme)"
                >
                  {{ opt.label }}
                </button>
              </div>
            </div>

            <div>
              <div class="mb-2 flex items-center justify-between text-sm">
                <span>字号</span>
                <span :class="ts.textMuted">{{ readerFontSize }}px</span>
              </div>
              <input class="w-full accent-[#ff5a2a]" type="range" min="16" max="30" :value="readerFontSize" @input="setFontSize(Number(($event.target as HTMLInputElement).value))" />
            </div>

            <div>
              <div class="mb-2 flex items-center justify-between text-sm">
                <span>行距</span>
                <span :class="ts.textMuted">{{ readerLineHeight }}</span>
              </div>
              <input class="w-full accent-[#ff5a2a]" type="range" min="1.4" max="2.8" step="0.1" :value="readerLineHeight" @input="setLineHeight(Number(($event.target as HTMLInputElement).value))" />
            </div>

            <div>
              <p class="mb-3 text-sm font-medium">页面宽度</p>
              <div class="grid grid-cols-3 gap-2">
                <button
                  v-for="opt in [
                    { key: 'narrow', label: '窄' },
                    { key: 'medium', label: '中' },
                    { key: 'wide', label: '宽' },
                  ]"
                  :key="opt.key"
                  class="rounded-full px-3 py-2 text-sm"
                  :class="readerMargin === opt.key ? 'bg-[#ff5a2a] text-white' : ts.subtle"
                  @click="setMargin(opt.key as ReaderMargin)"
                >
                  {{ opt.label }}
                </button>
              </div>
            </div>
          </div>
        </template>

        <template v-else-if="activePanel === 'comments'">
          <div class="mb-4 text-center">
            <h3 class="text-lg font-semibold">评论</h3>
            <p class="mt-1 text-xs" :class="ts.textMuted">
              {{ activeParagraphCommentCount }} 条 · 先看其他读者
            </p>
          </div>

          <div class="mb-4 rounded-xl border px-3 py-3" :class="[ts.border, ts.subtle]">
            <p class="line-clamp-3 text-sm leading-6" :class="ts.textSecondary">
              “{{ commentDraft?.selectedText || activeParagraphMeta?.paragraph.text || '当前段落' }}”
            </p>
          </div>

          <div v-if="!hasMyParagraphComment" class="mb-3 rounded-xl px-3 py-2 text-xs" :class="[ts.subtle, ts.textMuted]">
            发表你的评论后，就可以为其他读者的评论点赞。
          </div>
          <div v-else class="mb-3 rounded-xl px-3 py-2 text-xs" :class="[ts.subtle, ts.textMuted]">
            已发表本段评论，可以点赞其他读者的评论。
          </div>

          <div v-if="commentDraft && !hasMyParagraphComment" class="mb-4 rounded-xl border p-3" :class="[ts.border, ts.page]">
            <textarea
              v-model="commentDraftContent"
              class="min-h-20 w-full rounded-xl border bg-transparent px-3 py-2 text-sm outline-none focus:border-[#ff5a2a]"
              :class="ts.border"
              placeholder="发一条友善的评论..."
            />
            <div class="mt-3 flex justify-end gap-2">
              <button class="rounded-full px-4 py-2 text-sm" :class="ts.subtle" @click="clearCommentDraft">取消</button>
              <button class="rounded-full bg-[#ff5a2a] px-4 py-2 text-sm font-medium text-white" @click="submitParagraphComment">
                发布
              </button>
            </div>
          </div>

          <div class="max-h-[46vh] space-y-3 overflow-y-auto pr-1">
            <div v-for="item in orderedParagraphComments" :key="item.id" class="rounded-xl border p-3" :class="[ts.border, ts.page]">
              <div class="flex items-start gap-3">
                <div class="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-[#ff5a2a] text-xs font-semibold text-white">
                  {{ item.created_by.slice(0, 1) }}
                </div>
                <div class="min-w-0 flex-1">
                  <div class="flex items-center justify-between gap-3">
                    <span class="flex min-w-0 items-center gap-2">
                      <span class="truncate text-sm font-medium" :class="ts.text">{{ item.created_by }}</span>
                      <span v-if="item.is_mine" class="shrink-0 rounded-full px-2 py-0.5 text-[10px] text-[#ff5a2a]" :class="ts.subtle">我的</span>
                    </span>
                    <span class="shrink-0 text-xs" :class="ts.textMuted">{{ item.created_at }}</span>
                  </div>
                  <p v-if="item.selected_text !== activeParagraphMeta?.paragraph.text" class="mt-2 line-clamp-2 text-xs leading-5" :class="ts.textMuted">
                    “{{ item.selected_text }}”
                  </p>
                  <p class="mt-2 text-sm leading-6" :class="ts.text">{{ item.note || '这条评论还没有内容。' }}</p>
                </div>
              </div>
              <div class="ml-11 mt-3 flex items-center gap-3">
                <button
                  v-if="!item.is_mine"
                  class="rounded-full border px-3 py-1.5 text-xs transition disabled:cursor-not-allowed disabled:opacity-50"
                  :class="item.liked_by_me ? 'border-[#ff5a2a] bg-[#ff5a2a] text-white' : [ts.border, ts.textSecondary]"
                  :disabled="!hasMyParagraphComment || reactingHighlightIds.has(item.id)"
                  @click="toggleHighlightReaction(item)"
                >
                  {{ item.liked_by_me ? '已赞' : '赞' }} {{ item.likes_count || 0 }}
                </button>
                <span v-else class="text-xs" :class="ts.textMuted">我的评论放在下方展示</span>
              </div>
              <div v-if="item.comments.length" class="ml-11 mt-3 space-y-2 rounded-xl px-3 py-2" :class="ts.subtle">
                <p v-for="comment in item.comments" :key="comment.id" class="text-xs leading-5" :class="ts.textSecondary">
                  <span class="font-medium" :class="ts.text">{{ comment.author }}</span>：{{ comment.content }}
                </p>
              </div>
              <div class="ml-11 mt-3 flex gap-2">
                <input
                  v-model="replyDrafts[item.id]"
                  class="min-w-0 flex-1 rounded-full border bg-transparent px-3 py-2 text-xs outline-none"
                  :class="ts.border"
                  placeholder="回复"
                />
                <button class="rounded-full px-3 py-2 text-xs text-white bg-[#ff5a2a]" @click="submitCommentReply(item)">回复</button>
              </div>
            </div>
            <div v-if="activeParagraphComments.length === 0" class="rounded-xl p-6 text-center text-sm" :class="[ts.subtle, ts.textMuted]">
              当前段落还没有评论，来坐第一排。
            </div>
          </div>
        </template>

        <template v-else-if="activePanel === 'bookmarks'">
          <h3 class="text-lg font-semibold">书签</h3>
          <div class="mt-4 rounded-2xl p-3" :class="ts.subtle">
            <p class="text-sm">当前位置：{{ currentSectionTitle || '正文起始' }}</p>
            <textarea
              v-model="bookmarkNoteDraft"
              class="mt-3 min-h-16 w-full rounded-2xl border bg-transparent px-3 py-2 text-sm outline-none"
              :class="ts.border"
              placeholder="给这个位置补一句备注..."
            />
            <button class="mt-3 rounded-full bg-[#ff5a2a] px-4 py-2 text-sm font-medium text-white" @click="saveBookmark">
              {{ currentBookmark ? '更新当前位置' : '保存当前位置' }}
            </button>
          </div>
          <div class="mt-4 max-h-[42vh] space-y-2 overflow-y-auto pr-1">
            <div v-for="item in bookmarks" :key="item.id" class="rounded-2xl p-3 text-sm" :class="ts.subtle">
              <button class="block w-full text-left" @click="scrollToSection(item.section_id)">
                <span class="font-medium">{{ sectionTitleById[item.section_id] || item.section_id }}</span>
                <span class="mt-1 block text-xs" :class="ts.textMuted">{{ item.note || '书签位置' }}</span>
              </button>
              <button class="mt-2 text-xs" :class="ts.textMuted" @click="removeBookmark(item.id)">删除</button>
            </div>
            <div v-if="bookmarks.length === 0" class="rounded-2xl p-6 text-center text-sm" :class="[ts.subtle, ts.textMuted]">
              还没有书签，保存当前位置后会出现在这里。
            </div>
          </div>
        </template>
      </section>
    </div>
  </div>
</template>
