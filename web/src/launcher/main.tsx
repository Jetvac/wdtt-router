import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { App as AntApp } from 'antd'
import Launcher from './Launcher'
import { ThemeProvider } from '../theme'
import '../styles.css'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ThemeProvider>
      <AntApp>
        <Launcher />
      </AntApp>
    </ThemeProvider>
  </StrictMode>,
)
