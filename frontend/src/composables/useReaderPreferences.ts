import { ref, watch } from 'vue'

const themeStorageKey = 'reader_theme'
const fontSizeStorageKey = 'reader_font_size'
const lineHeightStorageKey = 'reader_line_height'
const marginStorageKey = 'reader_margin'

export type ReaderTheme = 'light' | 'dark' | 'green' | 'parchment'
export type ReaderMargin = 'narrow' | 'medium' | 'wide'

export function useReaderPreferences() {
  const readerTheme = ref<ReaderTheme>((localStorage.getItem(themeStorageKey) as ReaderTheme) || 'light')
  const readerFontSize = ref<number>(Number(localStorage.getItem(fontSizeStorageKey) || '20'))
  const readerLineHeight = ref<number>(Number(localStorage.getItem(lineHeightStorageKey) || '2.0'))
  const readerMargin = ref<ReaderMargin>((localStorage.getItem(marginStorageKey) as ReaderMargin) || 'medium')

  function setTheme(theme: ReaderTheme) {
    readerTheme.value = theme
    localStorage.setItem(themeStorageKey, theme)
  }

  function increaseFont() {
    readerFontSize.value = Math.min(30, readerFontSize.value + 1)
  }

  function decreaseFont() {
    readerFontSize.value = Math.max(16, readerFontSize.value - 1)
  }

  function setFontSize(size: number) {
    if (Number.isNaN(size)) {
      return
    }
    readerFontSize.value = Math.max(16, Math.min(30, Math.round(size)))
  }

  function setLineHeight(value: number) {
    if (Number.isNaN(value)) return
    readerLineHeight.value = Math.max(1.2, Math.min(3.0, Math.round(value * 10) / 10))
  }

  function setMargin(margin: ReaderMargin) {
    readerMargin.value = margin
  }

  watch(readerFontSize, (value) => {
    localStorage.setItem(fontSizeStorageKey, String(value))
  })

  watch(readerLineHeight, (value) => {
    localStorage.setItem(lineHeightStorageKey, String(value))
  })

  watch(readerMargin, (value) => {
    localStorage.setItem(marginStorageKey, value)
  })

  return {
    readerTheme,
    readerFontSize,
    readerLineHeight,
    readerMargin,
    setTheme,
    increaseFont,
    decreaseFont,
    setFontSize,
    setLineHeight,
    setMargin,
  }
}
