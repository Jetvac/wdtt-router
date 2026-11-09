import { useCallback, useEffect, useState } from 'react'
import { Avatar, Badge, Button, Card, Dropdown, Form, Input, Layout, Menu, Result, Space, Spin, Tooltip, Typography, theme } from 'antd'
import {
  ApartmentOutlined,
  AuditOutlined,
  CloudOutlined,
  CloudServerOutlined,
  DashboardOutlined,
  LockOutlined,
  LogoutOutlined,
  SwapOutlined,
  MobileOutlined,
  MoonOutlined,
  SunOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
  UnorderedListOutlined,
  UserOutlined,
  AppstoreOutlined,
} from '@ant-design/icons'
import { ApiError, get, isDesktop, post, setCsrf, setUnauthorizedHandler } from './api'
import { JobsProvider, useJobs } from './components/Jobs'
import Dashboard from './pages/Dashboard'
import Servers from './pages/Servers'
import Chain from './pages/Chain'
import Services from './pages/Services'
import Cloudflare from './pages/Cloudflare'
import JobsPage from './pages/JobsPage'
import Audit from './pages/Audit'
import Settings from './pages/Settings'
import Security from './pages/Security'
import WDTTPage from './pages/WDTT'
import { UpdateBanner } from './components/Update'
import { useThemeMode } from './theme'

function ThemeToggle() {
  const { mode, toggle } = useThemeMode()
  return (
    <Tooltip title={mode === 'dark' ? 'Светлая тема' : 'Тёмная тема'}>
      <Button type="text" icon={mode === 'dark' ? <SunOutlined /> : <MoonOutlined />} onClick={toggle} aria-label="Тема" />
    </Tooltip>
  )
}

const { Header, Sider, Content } = Layout

export const routes = [
  { key: '/', label: 'Обзор', icon: <DashboardOutlined />, el: Dashboard },
  { key: '/servers', label: 'Серверы', icon: <CloudServerOutlined />, el: Servers },
  { key: '/chain', label: 'Цепочка', icon: <ApartmentOutlined />, el: Chain },
  { key: '/wdtt', label: 'WDTT', icon: <MobileOutlined />, el: WDTTPage },
  { key: '/services', label: 'Сервисы', icon: <AppstoreOutlined />, el: Services },
  { key: '/security', label: 'Безопасность', icon: <SafetyCertificateOutlined />, el: Security },
  { key: '/cloudflare', label: 'Cloudflare Mesh', icon: <CloudOutlined />, el: Cloudflare },
  { key: '/jobs', label: 'Задачи', icon: <UnorderedListOutlined />, el: JobsPage },
  { key: '/audit', label: 'Журнал действий', icon: <AuditOutlined />, el: Audit },
  { key: '/settings', label: 'Настройки', icon: <SettingOutlined />, el: Settings },
]

export function navigate(path: string) {
  if (location.pathname !== path) {
    history.pushState(null, '', path)
    window.dispatchEvent(new PopStateEvent('popstate'))
  }
}

function usePath() {
  const [path, setPath] = useState(location.pathname)
  useEffect(() => {
    const on = () => setPath(location.pathname)
    window.addEventListener('popstate', on)
    return () => window.removeEventListener('popstate', on)
  }, [])
  return path
}

function useMobile() {
  const [m, setM] = useState(() => window.matchMedia('(max-width: 768px)').matches)
  useEffect(() => {
    const q = window.matchMedia('(max-width: 768px)')
    const on = () => setM(q.matches)
    q.addEventListener('change', on)
    return () => q.removeEventListener('change', on)
  }, [])
  return m
}

interface Me {
  username: string
  csrf: string
  version: string
}

export default function App() {
  const [me, setMe] = useState<Me | null>(null)
  const [checking, setChecking] = useState(true)

  const refresh = useCallback(async () => {
    try {
      const m = await get<Me>('/api/me')
      setCsrf(m.csrf)
      setMe(m)
    } catch {
      setMe(null)
    } finally {
      setChecking(false)
    }
  }, [])

  useEffect(() => {
    setUnauthorizedHandler(() => setMe(null))
    refresh()
  }, [refresh])

  if (checking)
    return (
      <div className="center-screen">
        <Spin size="large" />
      </div>
    )
  if (!me) return <Login onLogin={refresh} />
  return (
    <JobsProvider>
      <Shell me={me} onLogout={() => setMe(null)} />
    </JobsProvider>
  )
}

function Login({ onLogin }: { onLogin: () => void }) {
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const submit = async (v: { username: string; password: string }) => {
    setBusy(true)
    setError('')
    try {
      await post('/api/login', v)
      onLogin()
    } catch (e) {
      setError((e as ApiError).message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="login-bg">
      <Card className="login-card" variant="borderless">
        <Space orientation="vertical" size="large" style={{ width: '100%' }}>
          <div style={{ textAlign: 'center' }}>
            <img src="/favicon.svg" width={48} height={48} alt="" />
            <Typography.Title level={3} style={{ margin: '12px 0 4px' }}>
              WDTT Router
            </Typography.Title>
            <Typography.Text type="secondary">Цепочка VPN-серверов через Cloudflare Mesh</Typography.Text>
          </div>
          <Form layout="vertical" onFinish={submit} requiredMark={false} size="large">
            <Form.Item name="username" rules={[{ required: true, message: 'Введите логин' }]}>
              <Input prefix={<UserOutlined />} placeholder="Логин" autoComplete="username" autoFocus />
            </Form.Item>
            <Form.Item name="password" rules={[{ required: true, message: 'Введите пароль' }]}>
              <Input.Password prefix={<LockOutlined />} placeholder="Пароль" autoComplete="current-password" />
            </Form.Item>
            {error && <Typography.Paragraph type="danger">{error}</Typography.Paragraph>}
            <Button type="primary" htmlType="submit" block loading={busy}>
              Войти
            </Button>
          </Form>
        </Space>
      </Card>
    </div>
  )
}

function Shell({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const path = usePath()
  const [collapsed, setCollapsed] = useState(() => window.innerWidth < 992)
  const { token } = theme.useToken()
  const { active, setActive, version } = useJobs()
  const route = routes.find((r) => r.key === path) || null
  const Page = route?.el
  const mobile = useMobile()
  useEffect(() => {
    if (mobile) setCollapsed(true)
  }, [mobile])
  const go = (p: string) => {
    navigate(p)
    if (mobile) setCollapsed(true)
  }

  useEffect(() => {
    let stop = false
    const load = async () => {
      try {
        const jobs = await get<{ status: string }[]>('/api/jobs?limit=30')
        if (!stop) setActive(jobs.filter((j) => j.status === 'queued' || j.status === 'running').length)
      } catch {
        /* ignore */
      }
    }
    load()
    const t = setInterval(load, 5000)
    return () => {
      stop = true
      clearInterval(t)
    }
  }, [setActive, version])

  const logout = async () => {
    try {
      await post('/api/logout')
    } finally {
      onLogout()
    }
  }

  return (
    <Layout style={{ minHeight: '100vh' }}>
      {mobile && !collapsed && <div className="sider-mask" onClick={() => setCollapsed(true)} />}
      <Sider
        collapsible
        collapsed={collapsed}
        onCollapse={setCollapsed}
        trigger={null}
        width={232}
        collapsedWidth={mobile ? 0 : 64}
        theme="light"
        className={mobile ? 'mobile-sider' : undefined}
        style={{ borderRight: collapsed && mobile ? 'none' : `1px solid ${token.colorBorderSecondary}`, position: mobile ? 'fixed' : 'sticky', top: 0, height: '100vh', overflow: 'auto' }}
      >
        <div className="logo" onClick={() => go('/')}>
          <img src="/favicon.svg" width={28} height={28} alt="" />
          {!collapsed && <span>WDTT Router</span>}
        </div>
        <Menu mode="inline" selectedKeys={[route?.key || '/']} items={routes.map((r) => ({ key: r.key, icon: r.icon, label: r.label }))} onClick={(e) => go(e.key)} style={{ borderInlineEnd: 0 }} />
      </Sider>
      <Layout>
        <Header className="app-header" style={{ background: token.colorBgContainer, borderBottom: `1px solid ${token.colorBorderSecondary}` }}>
          <Space size="middle">
            <Button type="text" icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />} onClick={() => setCollapsed(!collapsed)} aria-label="Меню" />
            <Typography.Text strong style={{ fontSize: 16 }}>
              {route?.label || 'Страница не найдена'}
            </Typography.Text>
          </Space>
          <Space size="large">
            <ThemeToggle />
            <Tooltip title="Задачи">
              <Badge count={active} size="small">
                <Button type="text" icon={<UnorderedListOutlined />} onClick={() => navigate('/jobs')} aria-label="Задачи" />
              </Badge>
            </Tooltip>
            <Dropdown
              menu={{
                items: [
                  { key: 'settings', icon: <SettingOutlined />, label: 'Настройки и пароль', onClick: () => navigate('/settings') },
                  { type: 'divider' },
                  isDesktop()
                    ? { key: 'servers', icon: <SwapOutlined />, label: 'Серверы приложения', onClick: () => window.location.assign('/_app/') }
                    : { key: 'logout', icon: <LogoutOutlined />, label: 'Выйти', onClick: logout },
                ],
              }}
            >
              <Space style={{ cursor: 'pointer' }}>
                <Avatar size="small" style={{ background: token.colorPrimary }} icon={<UserOutlined />} />
                <span className="hide-sm">{me.username}</span>
              </Space>
            </Dropdown>
          </Space>
        </Header>
        <UpdateBanner />
        <Content className="app-content">
          {Page ? <Page /> : <Result status="404" title="404" subTitle="Такой страницы нет" extra={<Button onClick={() => navigate('/')}>На главную</Button>} />}
        </Content>
        <Layout.Footer className="app-footer">WDTT Router {me.version}</Layout.Footer>
      </Layout>
    </Layout>
  )
}
