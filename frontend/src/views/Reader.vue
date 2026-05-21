<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { useRoute, useRouter } from 'vue-router'
import {
  addBookToShelf,
  createBookComment,
  createHighlight,
  createHighlightComment,
  getReader,
  getReaderPreferences,
  saveReaderPreferences,
  type ReaderPayload,
} from '@/api/reader'
import { getToken } from '@/api/request'
import { getUserFavorites } from '@/api/user'
import { useReaderPreferences, type ReaderTheme, type ReaderMargin } from '@/composables/useReaderPreferences'
import { useReadingProgress } from '@/composables/useReadingProgress'

type SelectionDraft = {
  paragraphId: string
  startOffset: number
  endOffset: number
  selectedText: string
}

type PanelType = 'none' | 'outline' | 'settings' | 'highlight' | 'book-comments'

const route = useRoute()
const router = useRouter()
const bookId = computed(() => String(route.params.bookId || '1'))

const reader = ref<ReaderPayload | null>(null)
const loading = ref(false)
const addingToShelf = ref(false)
const isInShelf = ref(false)

const selectionDraft = ref<SelectionDraft | null>(null)
const draftNote = ref('')
const draftColor = ref('amber')
const activeHighlightId = ref<number | null>(null)
const highlightCommentDraft = ref('')
const bookCommentDraft = ref('')
const activeSectionId = ref<string>('')

const activePanel = ref<PanelType>('none')
const highlightModeEnabled = ref(false)
const showComments = ref(true)
const preferenceLoaded = ref(false)

const { readerTheme, readerFontSize, readerLineHeight, readerMargin, setTheme, setFontSize, setLineHeight, setMargin } = useReaderPreferences()
const { resumeIfNeeded, syncReadingProgress, getAnalyticsContext } = useReadingProgress(bookId, activeSectionId)

const colorMap: Record<string, string> = {
  amber: 'bg-amber-200/80 decoration-amber-500',
  sky: 'bg-sky-200/80 decoration-sky-500',
  rose: 'bg-rose-200/80 decoration-rose-500',
}

// Theme styles
const themeStyles: Record<ReaderTheme, { root: string; card: string; panel: string; text: string; textSecondary: string; textMuted: string; border: string; hover: string }> = {
  light: {
    root: 'min-h-screen bg-stone-100 text-stone-900',
    card: 'rounded-[1.5rem] bg-white shadow-sm',
    panel: 'border border-stone-200 bg-white text-stone-800',
    text: 'text-stone-900',
    textSecondary: 'text-stone-500',
    textMuted: 'text-stone-400',
    border: 'border-stone-100',
    hover: 'hover:bg-stone-50',
  },
  dark: {
    root: 'min-h-screen bg-[#0f1720] text-stone-100',
    card: 'rounded-[1.5rem] bg-[#111b28] shadow-sm',
    panel: 'border border-white/10 bg-[#1a2533] text-stone-100',
    text: 'text-stone-100',
    textSecondary: 'text-stone-300',
    textMuted: 'text-stone-400',
    border: 'border-white/10',
    hover: 'hover:bg-white/5',
  },
  green: {
    root: 'min-h-screen bg-[#e8f0e4] text-[#2d3a2a]',
    card: 'rounded-[1.5rem] bg-[#f0f5ec] shadow-sm',
    panel: 'border border-[#c5d6bc] bg-[#f0f5ec] text-[#2d3a2a]',
    text: 'text-[#2d3a2a]',
    textSecondary: 'text-[#4a5d42]',
    textMuted: 'text-[#6b7d63]',
    border: 'border-[#d4e0cd]',
    hover: 'hover:bg-[#dce6d6]',
  },
  parchment: {
    root: 'min-h-screen bg-[#f5eed5] text-[#3d3429]',
    card: 'rounded-[1.5rem] bg-[#faf6e8] shadow-sm',
    panel: 'border border-[#e0d9bf] bg-[#faf6e8] text-[#3d3429]',
    text: 'text-[#3d3429]',
    textSecondary: 'text-[#6b5d4a]',
    textMuted: 'text-[#8a7d6b]',
    border: 'border-[#e8e0ca]',
    hover: 'hover:bg-[#f0ead3]',
  },
}

const ts = computed(() => themeStyles[readerTheme.value] || themeStyles.light)

const rootClass = computed(() => ts.value.root)
const cardClass = computed(() => ts.value.card)
const panelCardClass = computed(() => ts.value.panel)

const contentMaxWidth = computed(() => {
  switch (readerMargin.value) {
    case 'narrow': return 'max-w-[800px]'
    case 'wide': return 'max-w-[1400px]'
    default: return 'max-w-[1100px]'
  }
})

const activeHighlight = computed(() => {
  if (!reader.value || activeHighlightId.value == null) {
    return null
  }
  return reader.value.highlights.find((item) => item.id === activeHighlightId.value) || null
})

const currentSectionIndex = computed(() => {
  if (!reader.value) return 0
  return Math.max(
    reader.value.sections.findIndex((section) => section.id === activeSectionId.value),
    0
  )
})

const progressPercent = computed(() => {
  if (!reader.value) return 0
  const totalSections = reader.value.sections.length || 1
  return Math.min(100, Math.round(((currentSectionIndex.value + 1) / totalSections) * 100))
})

const currentSectionTitle = computed(() => {
  if (!reader.value) return ''
  return reader.value.sections[currentSectionIndex.value]?.title || ''
})

const estimatedMinutesLeft = computed(() => {
  if (!reader.value) return 0
  const totalWords = reader.value.book.total_words || reader.value.book.word_count || 0
  if (totalWords <= 0) return 0
  const remainingPercent = 1 - progressPercent.value / 100
  const remainingWords = Math.round(totalWords * remainingPercent)
  return Math.max(1, Math.round(remainingWords / 400))
})

const hasPrevChapter = computed(() => currentSectionIndex.value > 0)
const hasNextChapter = computed(() => reader.value ? currentSectionIndex.value < reader.value.sections.length - 1 : false)

const toolbarStickyTop = computed(() => {
  const theme = readerTheme.value
  if (theme === 'dark') return 'bg-[#111b28]/92 border-white/10'
  if (theme === 'green') return 'bg-[#f0f5ec]/92 border-[#c5d6bc]'
  if (theme === 'parchment') return 'bg-[#faf6e8]/92 border-[#e0d9bf]'
  return 'bg-white/92 border-white/70'
})

async function loadReader() {
  loading.value = true
  try {
    const payload = await getReader(bookId.value, getAnalyticsContext())
    reader.value = payload
    activeSectionId.value = payload.sections[0]?.id || ''
    activeHighlightId.value = payload.highlights[0]?.id ?? null
    await resumeIfNeeded(route.query.resume === '1')
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
    const currentBookId = Number(bookId.value)
    isInShelf.value = favorites.items.some((item) => item.id === currentBookId)
  } catch (_error) {
    isInShelf.value = false
  }
}

async function loadReaderPreferences() {
  try {
    const data = await getReaderPreferences()
    setTheme(data.theme === 'dark' ? 'dark' : data.theme === 'green' ? 'green' : data.theme === 'parchment' ? 'parchment' : 'light')
    setFontSize(Number(data.font_size) || 20)
    setLineHeight(Number(data.line_height) || 2.0)
    setMargin((data.margin as ReaderMargin) || 'medium')
    showComments.value = data.show_comments !== false
  } catch (_error) {
    // Keep defaults when preference loading fails.
  } finally {
    preferenceLoaded.value = true
  }
}

async function persistReaderPreferences() {
  if (!preferenceLoaded.value || !getToken()) {
    return
  }
  try {
    await saveReaderPreferences({
      theme: readerTheme.value,
      font_size: readerFontSize.value,
      line_height: readerLineHeight.value,
      margin: readerMargin.value,
      show_highlights: true,
      show_comments: showComments.value,
    })
  } catch (_error) {
    // Do not block reading flow on preference save failures.
  }
}

function clearSelectionDraft() {
  selectionDraft.value = null
  draftNote.value = ''
  draftColor.value = 'amber'
  const selection = window.getSelection()
  selection?.removeAllRanges()
}

function togglePanel(panel: PanelType) {
  activePanel.value = activePanel.value === panel ? 'none' : panel
}

function toggleHighlightMode() {
  highlightModeEnabled.value = !highlightModeEnabled.value
  if (!highlightModeEnabled.value) {
    clearSelectionDraft()
  } else {
    ElMessage.info('划线模式已开启，请在正文里选中同一段内的文字')
  }
}

function toggleCommentVisibility() {
  showComments.value = !showComments.value
  if (!showComments.value && (activePanel.value === 'highlight' || activePanel.value === 'book-comments')) {
    activePanel.value = 'none'
  }
}

function scrollToSection(sectionId: string) {
  activeSectionId.value = sectionId
  document.getElementById(sectionId)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
}

function goToPrevChapter() {
  if (!hasPrevChapter.value || !reader.value) return
  const prev = reader.value.sections[currentSectionIndex.value - 1]
  if (prev) scrollToSection(prev.id)
}

function goToNextChapter() {
  if (!hasNextChapter.value || !reader.value) return
  const next = reader.value.sections[currentSectionIndex.value + 1]
  if (next) scrollToSection(next.id)
}

function handleSelection() {
  if (!highlightModeEnabled.value) {
    return
  }

  const selection = window.getSelection()
  if (!selection || selection.rangeCount === 0 || selection.isCollapsed) {
    return
  }

  const range = selection.getRangeAt(0)
  const startParagraph = (range.startContainer.nodeType === Node.TEXT_NODE
    ? range.startContainer.parentElement
    : (range.startContainer as Element)
  )?.closest?.('[data-paragraph-id]') as HTMLElement | null
  const endParagraph = (range.endContainer.nodeType === Node.TEXT_NODE
    ? range.endContainer.parentElement
    : (range.endContainer as Element)
  )?.closest?.('[data-paragraph-id]') as HTMLElement | null

  if (!startParagraph || !endParagraph || startParagraph !== endParagraph) {
    ElMessage.info('当前只支持在同一段落内划线')
    clearSelectionDraft()
    return
  }

  const paragraphId = startParagraph.dataset.paragraphId
  if (!paragraphId) {
    clearSelectionDraft()
    return
  }

  const preSelectionRange = range.cloneRange()
  preSelectionRange.selectNodeContents(startParagraph)
  preSelectionRange.setEnd(range.startContainer, range.startOffset)

  const startOffset = preSelectionRange.toString().length
  const selectedText = range.toString().trim()
  const endOffset = startOffset + selectedText.length
  if (!selectedText) {
    clearSelectionDraft()
    return
  }

  selectionDraft.value = { paragraphId, startOffset, endOffset, selectedText }
  activeHighlightId.value = null
}

async function submitHighlight() {
  if (!selectionDraft.value) {
    return
  }

  try {
    const response = await createHighlight(bookId.value, {
      paragraph_id: selectionDraft.value.paragraphId,
      start_offset: selectionDraft.value.startOffset,
      end_offset: selectionDraft.value.endOffset,
      selected_text: selectionDraft.value.selectedText,
      note: draftNote.value,
      color: draftColor.value,
    })
    reader.value?.highlights.push(response.highlight)
    activeHighlightId.value = response.highlight.id
    activePanel.value = 'highlight'
    clearSelectionDraft()
    ElMessage.success('划线已保存')
  } catch (_error) {
    ElMessage.error('划线保存失败，请先登录后重试')
  }
}

async function submitHighlightComment() {
  if (!activeHighlight.value || !highlightCommentDraft.value.trim()) {
    return
  }

  try {
    const response = await createHighlightComment(bookId.value, activeHighlight.value.id, {
      content: highlightCommentDraft.value,
    })
    activeHighlight.value.comments.push(response.comment)
    highlightCommentDraft.value = ''
    ElMessage.success('评论已发布')
  } catch (_error) {
    ElMessage.error('评论发布失败，请先登录后重试')
  }
}

async function submitBookComment() {
  if (!bookCommentDraft.value.trim() || !reader.value) {
    return
  }
  try {
    const response = await createBookComment(bookId.value, { content: bookCommentDraft.value })
    reader.value.book_comments.unshift(response.comment)
    bookCommentDraft.value = ''
    ElMessage.success('书评发布成功')
  } catch (_error) {
    ElMessage.error('书评发布失败，请先登录后重试')
  }
}

async function handleAddToShelf() {
  if (isInShelf.value) {
    return
  }
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

function handleScroll() {
  if (!reader.value) {
    return
  }

  let currentSection = reader.value.sections[0]?.id || ''
  reader.value.sections.forEach((section) => {
    const element = document.getElementById(section.id)
    if (element && element.getBoundingClientRect().top <= 140) {
      currentSection = section.id
    }
  })

  if (currentSection !== activeSectionId.value) {
    activeSectionId.value = currentSection
  }
  syncReadingProgress(false)
}

function handleKeydown(e: KeyboardEvent) {
  if (e.key === 'ArrowLeft') {
    goToPrevChapter()
  } else if (e.key === 'ArrowRight') {
    goToNextChapter()
  } else if (e.key === 'Escape' && activePanel.value !== 'none') {
    activePanel.value = 'none'
  }
}

onMounted(async () => {
  await loadReaderPreferences()
  await loadShelfState()
  await loadReader()
  window.addEventListener('scroll', handleScroll, { passive: true })
  document.addEventListener('mouseup', handleSelection)
  document.addEventListener('keydown', handleKeydown)
})

onBeforeUnmount(() => {
  syncReadingProgress(true)
  window.removeEventListener('scroll', handleScroll)
  document.removeEventListener('mouseup', handleSelection)
  document.removeEventListener('keydown', handleKeydown)
})

watch(
  () => route.params.bookId,
  async () => {
    clearSelectionDraft()
    activePanel.value = 'none'
    await nextTick()
    await loadShelfState()
    await loadReader()
  }
)

watch([readerTheme, readerFontSize, readerLineHeight, readerMargin, showComments], () => {
  persistReaderPreferences()
})
</script>

<template>
  <div :class="rootClass" class="pb-14">
    <main class="mx-auto px-4 py-6 md:px-8" :class="contentMaxWidth">
      <div v-if="loading" :class="[cardClass, ts.textSecondary]" class="p-10 text-center">正在加载正文...</div>

      <template v-else-if="reader">
        <!-- Top info bar -->
        <section
          class="sticky top-3 z-30 mb-6 overflow-hidden rounded-[1.25rem] border px-5 py-4 shadow-lg backdrop-blur-xl md:top-4 md:px-6"
          :class="toolbarStickyTop"
        >
          <div class="min-w-0">
            <h1 class="truncate text-xl font-semibold">{{ reader.book.title }}</h1>
            <p class="text-sm" :class="ts.textSecondary">{{ reader.book.author }}</p>
            <p class="mt-1 text-xs" :class="ts.textMuted">
              <span v-if="currentSectionTitle">正在阅读：{{ currentSectionTitle }} · </span>
              进度约 {{ progressPercent }}%
              <span v-if="estimatedMinutesLeft > 0"> · 预计 {{ estimatedMinutesLeft }} 分钟读完</span>
            </p>
          </div>
          <div class="flex flex-wrap items-center gap-2 lg:justify-end">
            <button class="rounded-full border px-4 py-2 text-sm" :class="ts.border" @click="router.push('/')">回到首页</button>
            <button class="rounded-full border px-4 py-2 text-sm" :class="ts.border" @click="router.push(`/books/${bookId}`)">返回详情</button>
            <button class="rounded-full border px-4 py-2 text-sm" :class="ts.border" @click="router.push('/user/library')">我的书架</button>
            <button
              class="rounded-full bg-emerald-500 px-4 py-2 text-sm font-medium text-white disabled:opacity-60"
              :disabled="addingToShelf || isInShelf"
              @click="handleAddToShelf"
            >
              {{ addingToShelf ? '加入中...' : isInShelf ? '已在书架' : '加入书架' }}
            </button>
          </div>
          <div class="mt-4 flex items-center gap-3">
            <div
              class="h-2 flex-1 overflow-hidden rounded-full"
              :class="readerTheme === 'dark' ? 'bg-white/10' : readerTheme === 'green' ? 'bg-[#c5d6bc]' : readerTheme === 'parchment' ? 'bg-[#e0d9bf]' : 'bg-stone-200'"
            >
              <div
                class="h-full rounded-full bg-emerald-500 transition-all duration-300"
                :style="{ width: `${progressPercent}%` }"
              />
            </div>
            <span class="text-xs font-medium tabular-nums text-emerald-600" :class="readerTheme === 'dark' ? 'text-emerald-300' : ''">
              {{ progressPercent }}%
            </span>
          </div>
        </section>

        <!-- Content area -->
        <article :class="cardClass" class="p-6 md:p-8">
          <!-- Selection draft -->
          <div
            v-if="selectionDraft"
            class="mb-8 rounded-[1.2rem] border border-amber-200 bg-amber-50 p-5 text-stone-900"
          >
            <p class="text-xs uppercase tracking-[0.3em] text-amber-700">新建划线</p>
            <p class="mt-3 rounded-2xl bg-white px-4 py-4 text-lg leading-8 shadow-sm">"{{ selectionDraft.selectedText }}"</p>
            <div class="mt-4 flex flex-wrap gap-2">
              <button
                v-for="option in ['amber', 'sky', 'rose']"
                :key="option"
                :class="[
                  'rounded-full px-3 py-2 text-xs font-medium uppercase tracking-[0.25em]',
                  draftColor === option ? 'bg-stone-900 text-white' : 'bg-white text-stone-500',
                ]"
                @click="draftColor = option"
              >
                {{ option }}
              </button>
            </div>
            <textarea
              v-model="draftNote"
              class="mt-4 min-h-24 w-full rounded-2xl border border-amber-100 bg-white px-4 py-3 outline-none focus:border-stone-400"
              placeholder="写下你对这段文字的感受..."
            />
            <div class="mt-4 flex flex-wrap gap-3">
              <button class="rounded-full bg-stone-900 px-5 py-2.5 text-sm font-medium text-white" @click="submitHighlight">
                保存划线
              </button>
              <button class="rounded-full bg-white px-5 py-2.5 text-sm font-medium text-stone-500" @click="clearSelectionDraft">
                取消
              </button>
            </div>
          </div>

          <!-- Sections -->
          <section
            v-for="(section, sectionIdx) in reader.sections"
            :id="section.id"
            :key="section.id"
            class="scroll-mt-40 border-b py-7 first:pt-0 last:border-b-0 md:scroll-mt-44"
            :class="ts.border"
          >
            <p class="text-xs uppercase tracking-[0.35em]" :class="ts.textMuted">
              {{ sectionIdx === 0 ? '起始' : `第 ${sectionIdx + 1} 章` }}
            </p>
            <h3 class="mt-3 text-3xl font-semibold">{{ section.title }}</h3>
            <p class="mt-3 max-w-2xl text-sm leading-7" :class="ts.textSecondary">
              {{ section.summary }}
            </p>

            <div class="mt-6 space-y-6">
              <p
                v-for="paragraph in section.paragraphs"
                :key="paragraph.id"
                :data-paragraph-id="paragraph.id"
                class="rounded-3xl px-3 py-3 transition"
                :class="[ts.text, ts.hover]"
                :style="{ fontSize: `${readerFontSize}px`, lineHeight: String(readerLineHeight) }"
              >
                {{ paragraph.text }}
              </p>
            </div>
          </section>

          <!-- Chapter navigation -->
          <div class="mt-8 flex items-center justify-between gap-4">
            <button
              class="flex items-center gap-2 rounded-full border px-5 py-3 text-sm font-medium transition disabled:opacity-40 disabled:cursor-not-allowed"
              :class="[ts.border, ts.text]"
              :disabled="!hasPrevChapter"
              @click="goToPrevChapter"
            >
              <span>&larr;</span>
              <span>上一章</span>
            </button>
            <span class="text-xs" :class="ts.textMuted">{{ currentSectionIndex + 1 }} / {{ reader.sections.length }}</span>
            <button
              class="flex items-center gap-2 rounded-full border px-5 py-3 text-sm font-medium transition disabled:opacity-40 disabled:cursor-not-allowed"
              :class="[ts.border, ts.text]"
              :disabled="!hasNextChapter"
              @click="goToNextChapter"
            >
              <span>下一章</span>
              <span>&rarr;</span>
            </button>
          </div>
        </article>
      </template>
    </main>

    <!-- Toolbar: desktop right side, mobile bottom -->
    <div class="fixed bottom-4 right-3 z-40 md:right-5 md:top-1/2 md:-translate-y-1/2">
      <div class="rounded-[1.2rem] bg-[#1b1f28] p-2 shadow-2xl">
        <div class="flex gap-2 md:flex-col">
          <button
            class="h-11 w-11 rounded-full text-xs font-medium"
            :class="activePanel === 'outline' ? 'bg-emerald-500 text-white' : 'bg-[#101319] text-stone-200'"
            title="目录"
            @click="togglePanel('outline')"
          >
            目录
          </button>
          <button
            class="h-11 w-11 rounded-full text-xs font-medium"
            :class="activePanel === 'settings' ? 'bg-emerald-500 text-white' : 'bg-[#101319] text-stone-200'"
            title="设置"
            @click="togglePanel('settings')"
          >
            设置
          </button>
          <button
            class="h-11 w-11 rounded-full text-xs font-medium"
            :class="highlightModeEnabled ? 'bg-amber-500 text-white' : 'bg-[#101319] text-stone-200'"
            title="划线"
            @click="toggleHighlightMode"
          >
            划线
          </button>
          <button
            class="h-11 w-11 rounded-full text-xs font-medium"
            :class="showComments ? 'bg-[#101319] text-stone-200' : 'bg-rose-500 text-white'"
            :title="showComments ? '隐藏评论' : '显示评论'"
            @click="toggleCommentVisibility"
          >
            {{ showComments ? '隐评' : '显评' }}
          </button>
          <button
            class="h-11 w-11 rounded-full text-xs font-medium"
            :class="activePanel === 'highlight' ? 'bg-emerald-500 text-white' : 'bg-[#101319] text-stone-200'"
            title="批注"
            @click="togglePanel('highlight')"
          >
            批注
          </button>
          <button
            class="h-11 w-11 rounded-full text-xs font-medium"
            :class="activePanel === 'book-comments' ? 'bg-emerald-500 text-white' : 'bg-[#101319] text-stone-200'"
            title="书评"
            @click="togglePanel('book-comments')"
          >
            书评
          </button>
        </div>
      </div>
    </div>

    <!-- Panels -->
    <div
      v-if="activePanel !== 'none' && reader"
      class="fixed left-4 right-4 bottom-20 z-40 rounded-[1.2rem] p-4 shadow-2xl md:left-auto md:right-20 md:top-1/2 md:w-[360px] md:-translate-y-1/2"
      :class="panelCardClass"
    >
      <!-- Outline panel -->
      <template v-if="activePanel === 'outline'">
        <h3 class="mb-3 text-lg font-semibold">目录</h3>
        <div class="max-h-[55vh] space-y-2 overflow-y-auto pr-1">
          <button
            v-for="item in reader.outline"
            :key="item.id"
            :class="[
              'block w-full rounded-xl px-3 py-2 text-left text-sm transition',
              item.level === 2 ? 'ml-3 w-[calc(100%-0.75rem)]' : 'font-medium',
              activeSectionId === item.id ? 'bg-emerald-500 text-white' : 'bg-black/10 hover:bg-black/20',
            ]"
            @click="scrollToSection(item.id)"
          >
            {{ item.title }}
          </button>
        </div>
      </template>

      <!-- Settings panel -->
      <template v-else-if="activePanel === 'settings'">
        <h3 class="mb-4 text-lg font-semibold">阅读设置</h3>
        <div class="space-y-5">
          <!-- Theme -->
          <div>
            <p class="mb-2 text-sm font-medium">主题</p>
            <div class="grid grid-cols-4 gap-2">
              <button
                v-for="opt in [
                  { key: 'light', label: '浅色', bg: 'bg-stone-100', border: 'border-stone-300' },
                  { key: 'dark', label: '深色', bg: 'bg-[#0f1720]', border: 'border-white/20' },
                  { key: 'green', label: '护眼绿', bg: 'bg-[#e8f0e4]', border: 'border-[#c5d6bc]' },
                  { key: 'parchment', label: '羊皮纸', bg: 'bg-[#f5eed5]', border: 'border-[#e0d9bf]' },
                ]"
                :key="opt.key"
                :class="[
                  'flex flex-col items-center gap-1 rounded-xl border-2 px-2 py-2 text-xs transition',
                  readerTheme === opt.key ? 'border-emerald-500' : opt.border,
                  opt.bg,
                ]"
                @click="setTheme(opt.key as ReaderTheme)"
              >
                <span class="block h-5 w-5 rounded-full" :class="opt.bg" />
                <span :class="opt.key === 'dark' ? 'text-stone-200' : ''">{{ opt.label }}</span>
              </button>
            </div>
          </div>

          <!-- Font size -->
          <div>
            <div class="mb-2 flex items-center justify-between">
              <p class="text-sm font-medium">字号</p>
              <span class="text-xs" :class="ts.textMuted">{{ readerFontSize }}px</span>
            </div>
            <input
              class="w-full accent-emerald-500"
              type="range"
              min="16"
              max="30"
              :value="readerFontSize"
              @input="setFontSize(Number(($event.target as HTMLInputElement).value))"
            />
          </div>

          <!-- Line height -->
          <div>
            <div class="mb-2 flex items-center justify-between">
              <p class="text-sm font-medium">行距</p>
              <span class="text-xs" :class="ts.textMuted">{{ readerLineHeight }}</span>
            </div>
            <input
              class="w-full accent-emerald-500"
              type="range"
              min="1.2"
              max="3.0"
              step="0.1"
              :value="readerLineHeight"
              @input="setLineHeight(Number(($event.target as HTMLInputElement).value))"
            />
            <div class="mt-1 flex justify-between text-xs" :class="ts.textMuted">
              <span>紧凑</span>
              <span>宽松</span>
            </div>
          </div>

          <!-- Margin -->
          <div>
            <p class="mb-2 text-sm font-medium">页面宽度</p>
            <div class="flex gap-2">
              <button
                v-for="opt in [
                  { key: 'narrow', label: '窄' },
                  { key: 'medium', label: '中' },
                  { key: 'wide', label: '宽' },
                ]"
                :key="opt.key"
                :class="[
                  'flex-1 rounded-full px-3 py-2 text-sm transition',
                  readerMargin === opt.key ? 'bg-emerald-500 text-white' : 'bg-black/10',
                ]"
                @click="setMargin(opt.key as ReaderMargin)"
              >
                {{ opt.label }}
              </button>
            </div>
          </div>
        </div>
      </template>

      <!-- Highlight panel -->
      <template v-else-if="activePanel === 'highlight'">
        <h3 class="mb-3 text-lg font-semibold">划线批注</h3>
        <div v-if="!showComments" class="text-sm" :class="ts.textMuted">评论已隐藏，请先打开"显评"。</div>
        <div v-else-if="activeHighlight">
          <p
            :class="[
              'rounded-2xl px-3 py-3 text-base leading-7 underline decoration-2 underline-offset-4',
              colorMap[activeHighlight.color] || colorMap.amber,
            ]"
          >
            {{ activeHighlight.selected_text }}
          </p>
          <p class="mt-3 text-sm leading-7">{{ activeHighlight.note || '这条划线还没有补充批注。' }}</p>

          <div class="mt-4 max-h-[28vh] space-y-2 overflow-y-auto pr-1">
            <div
              v-for="comment in activeHighlight.comments"
              :key="comment.id"
              class="rounded-2xl bg-black/10 px-3 py-3 text-sm"
            >
              <div class="flex items-center justify-between text-xs opacity-70">
                <span>{{ comment.author }}</span>
                <span>{{ comment.created_at }}</span>
              </div>
              <p class="mt-1 leading-6">{{ comment.content }}</p>
            </div>
          </div>

          <textarea
            v-model="highlightCommentDraft"
            class="mt-4 min-h-20 w-full rounded-2xl border border-stone-300 bg-transparent px-3 py-2 text-sm outline-none"
            placeholder="补充一点你的理解..."
          />
          <button class="mt-3 rounded-full bg-stone-900 px-4 py-2 text-sm text-white" @click="submitHighlightComment">
            发布评论
          </button>
        </div>
        <div v-else class="text-sm" :class="ts.textMuted">先在正文中划线，保存后就会显示在这里。</div>
      </template>

      <!-- Book comments panel -->
      <template v-else-if="activePanel === 'book-comments'">
        <h3 class="mb-3 text-lg font-semibold">本书评论</h3>
        <div v-if="!showComments" class="text-sm" :class="ts.textMuted">评论已隐藏，请先打开"显评"。</div>
        <template v-else>
          <textarea
            v-model="bookCommentDraft"
            class="min-h-24 w-full rounded-2xl border border-stone-300 bg-transparent px-3 py-2 text-sm outline-none"
            placeholder="写下你对这本书的看法..."
          />
          <button class="mt-3 rounded-full bg-emerald-500 px-4 py-2 text-sm font-medium text-white" @click="submitBookComment">
            发表书评
          </button>

          <div class="mt-4 max-h-[35vh] space-y-2 overflow-y-auto pr-1">
            <div
              v-for="comment in reader.book_comments"
              :key="comment.id"
              class="rounded-2xl bg-black/10 px-3 py-3 text-sm"
            >
              <div class="flex items-center justify-between text-xs opacity-70">
                <span>{{ comment.author }}</span>
                <span>{{ comment.created_at }}</span>
              </div>
              <p class="mt-1 leading-6">{{ comment.content }}</p>
            </div>
          </div>
        </template>
      </template>
    </div>
  </div>
</template>
