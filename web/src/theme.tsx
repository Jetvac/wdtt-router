import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { ConfigProvider, theme } from 'antd'
import ruRU from 'antd/locale/ru_RU'

type Mode = 'light' | 'dark'

const Ctx = createContext<{ mode: Mode; toggle: () => void }>({ mode: 'light', toggle: () => {} })
export const useThemeMode = () => useContext(Ctx)

function initial(): Mode {
  try {
    const saved = localStorage.getItem('theme')
    if (saved === 'light' || saved === 'dark') return saved
  } catch {
    /* storage unavailable */
  }
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

/** Light or dark theme: follows the system until the user picks one. */
export function ThemeProvider({ children }: { children: ReactNode }) {
  const [mode, setMode] = useState<Mode>(initial)
  useEffect(() => {
    document.documentElement.dataset.theme = mode
  }, [mode])
  useEffect(() => {
    const mq = window.matchMedia?.('(prefers-color-scheme: dark)')
    const on = (e: MediaQueryListEvent) => {
      try {
        if (localStorage.getItem('theme')) return
      } catch {
        /* ignore */
      }
      setMode(e.matches ? 'dark' : 'light')
    }
    mq?.addEventListener('change', on)
    return () => mq?.removeEventListener('change', on)
  }, [])
  const toggle = () =>
    setMode((m) => {
      const next = m === 'dark' ? 'light' : 'dark'
      try {
        localStorage.setItem('theme', next)
      } catch {
        /* ignore */
      }
      return next
    })
  const dark = mode === 'dark'
  return (
    <Ctx.Provider value={{ mode, toggle }}>
      <ConfigProvider
        locale={ruRU}
        theme={{
          algorithm: dark ? theme.darkAlgorithm : theme.defaultAlgorithm,
          token: { colorPrimary: '#1677ff', borderRadius: 6, fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif" },
          components: { Layout: { headerHeight: 56, headerPadding: '0 20px', bodyBg: dark ? '#000000' : '#f5f5f5' } },
        }}
      >
        {children}
      </ConfigProvider>
    </Ctx.Provider>
  )
}
