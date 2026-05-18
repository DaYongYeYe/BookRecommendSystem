<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'

const props = defineProps<{
  modelValue: string
  placeholder?: string
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', value: string): void
  (e: 'save'): void
}>()

const content = ref(props.modelValue)
const isFullscreen = ref(false)
const autoSaveStatus = ref<'idle' | 'saving' | 'saved' | 'error'>('idle')
const textareaRef = ref<HTMLTextAreaElement | null>(null)
let autoSaveTimer: ReturnType<typeof setInterval> | null = null
let statusResetTimer: ReturnType<typeof setTimeout> | null = null

watch(() => props.modelValue, (val) => {
  if (val !== content.value) content.value = val
})

watch(content, (val) => {
  emit('update:modelValue', val)
})

const charCount = computed(() => content.value.length)
const wordCount = computed(() => {
  const text = content.value.trim()
  if (!text) return 0
  // Count Chinese chars + English words
  const chinese = (text.match(/[一-鿿]/g) || []).length
  const english = text.replace(/[一-鿿]/g, ' ').split(/\s+/).filter(Boolean).length
  return chinese + english
})

function toggleFullscreen() {
  isFullscreen.value = !isFullscreen.value
}

function handleKeydown(e: KeyboardEvent) {
  if ((e.ctrlKey || e.metaKey) && e.key === 's') {
    e.preventDefault()
    triggerSave()
  }
  if (e.key === 'Escape' && isFullscreen.value) {
    isFullscreen.value = false
  }
}

function triggerSave() {
  autoSaveStatus.value = 'saving'
  emit('save')
  // The parent should handle the actual save and can call setSaveStatus
}

function setSaveStatus(status: 'idle' | 'saving' | 'saved' | 'error') {
  autoSaveStatus.value = status
  if (status === 'saved') {
    if (statusResetTimer) clearTimeout(statusResetTimer)
    statusResetTimer = setTimeout(() => {
      autoSaveStatus.value = 'idle'
    }, 3000)
  }
}

function startAutoSave() {
  autoSaveTimer = setInterval(() => {
    if (content.value.trim()) {
      autoSaveStatus.value = 'saving'
      emit('save')
    }
  }, 30000)
}

onMounted(() => {
  startAutoSave()
  document.addEventListener('keydown', handleKeydown)
})

onBeforeUnmount(() => {
  if (autoSaveTimer) clearInterval(autoSaveTimer)
  if (statusResetTimer) clearTimeout(statusResetTimer)
  document.removeEventListener('keydown', handleKeydown)
})

defineExpose({ setSaveStatus })
</script>

<template>
  <div :class="['editor-wrap', { fullscreen: isFullscreen }]">
    <div class="editor-toolbar">
      <div class="editor-stats">
        <span class="stat-item">{{ charCount }} 字</span>
        <span class="stat-sep">|</span>
        <span class="stat-item">约 {{ wordCount }} 词</span>
      </div>
      <div class="editor-actions">
        <span :class="['save-status', autoSaveStatus]">
          <template v-if="autoSaveStatus === 'saving'">保存中...</template>
          <template v-else-if="autoSaveStatus === 'saved'">已自动保存</template>
          <template v-else-if="autoSaveStatus === 'error'">保存失败</template>
          <template v-else>Ctrl+S 保存</template>
        </span>
        <button class="toolbar-btn" @click="triggerSave" title="保存 (Ctrl+S)">
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M13 15H3a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1h8l3 3v10a1 1 0 0 1-1 1Z" stroke="currentColor" stroke-width="1.5"/><path d="M10 15V9H6v6M6 1.5V5h5" stroke="currentColor" stroke-width="1.5"/></svg>
        </button>
        <button class="toolbar-btn" @click="toggleFullscreen" :title="isFullscreen ? '退出全屏' : '全屏编辑'">
          <svg v-if="!isFullscreen" width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M2 6V2h4M14 6V2h-4M2 10v4h4M14 10v4h-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
          <svg v-else width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M6 2v4H2M14 6V2h-4M6 14v-4H2M14 10v4h-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </button>
      </div>
    </div>
    <textarea
      ref="textareaRef"
      v-model="content"
      class="editor-textarea"
      :placeholder="placeholder || '请输入章节正文...'"
      spellcheck="false"
    />
  </div>
</template>

<style scoped>
.editor-wrap {
  display: flex;
  flex-direction: column;
  border: 1px solid #d6d3d1;
  border-radius: 12px;
  overflow: hidden;
  background: #fff;
  transition: all 0.2s;
}

.editor-wrap:focus-within {
  border-color: #1c1917;
  box-shadow: 0 0 0 2px rgba(28, 25, 23, 0.08);
}

.editor-wrap.fullscreen {
  position: fixed;
  inset: 0;
  z-index: 2000;
  border-radius: 0;
  background: #fff;
}

.editor-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 12px;
  border-bottom: 1px solid #e7e5e4;
  background: #fafaf9;
}

.editor-stats {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  color: #78716c;
}

.stat-sep {
  color: #d6d3d1;
}

.editor-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.save-status {
  font-size: 12px;
  color: #78716c;
  transition: color 0.2s;
}

.save-status.saving {
  color: #d97706;
}

.save-status.saved {
  color: #059669;
}

.save-status.error {
  color: #dc2626;
}

.toolbar-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  border-radius: 8px;
  border: none;
  background: transparent;
  color: #57534e;
  cursor: pointer;
  transition: all 0.15s;
}

.toolbar-btn:hover {
  background: #e7e5e4;
  color: #1c1917;
}

.editor-textarea {
  flex: 1;
  min-height: 400px;
  padding: 16px 20px;
  border: none;
  outline: none;
  resize: vertical;
  font-size: 15px;
  line-height: 1.8;
  color: #1c1917;
  font-family: 'Noto Serif SC', 'Source Han Serif CN', Georgia, serif;
}

.editor-wrap.fullscreen .editor-textarea {
  min-height: 0;
  flex: 1;
  resize: none;
}

.editor-textarea::placeholder {
  color: #a8a29e;
}
</style>
