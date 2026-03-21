import { ref, watch } from 'vue'

const themeStorageKey = 'reader_theme'
const fontSizeStorageKey = 'reader_font_size'

export function useReaderPreferences() {
  const readerTheme = ref<'light' | 'dark'>((localStorage.getItem(themeStorageKey) as 'light' | 'dark') || 'light')
  const readerFontSize = ref<number>(Number(localStorage.getItem(fontSizeStorageKey) || '20'))

  function setTheme(theme: 'light' | 'dark') {
    readerTheme.value = theme
    localStorage.setItem(themeStorageKey, theme)
  }

  function increaseFont() {
    readerFontSize.value = Math.min(30, readerFontSize.value + 1)
  }

  function decreaseFont() {
    readerFontSize.value = Math.max(16, readerFontSize.value - 1)
  }

  watch(readerFontSize, (value) => {
    localStorage.setItem(fontSizeStorageKey, String(value))
  })

  return {
    readerTheme,
    readerFontSize,
    setTheme,
    increaseFont,
    decreaseFont,
  }
}
