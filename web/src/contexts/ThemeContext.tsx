import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react'

export type Theme = 'obsidian' | 'aurum' | 'lapis' | 'arch' | 'vault'
export type View = 'command' | 'hex' | 'security' | 'lab' | 'vault' | 'zk_matrix' | 'tensor_v6' | 'asm_studio' | 'war_room'
type Density = 'compact' | 'comfortable'
type CornerRadius = 0 | 6 | 12

// URL sub-page routing: each view owns a real pathname (shareable, back/forward
// works via popstate). vite dev serves the SPA fallback for all of these.
export const VIEW_ROUTES: Record<View, string> = {
  command: '/main',
  hex: '/hexinspector',
  security: '/security',
  lab: '/lab',
  vault: '/vault',
  zk_matrix: '/zk-matrix',
  tensor_v6: '/tensor-v6',
  asm_studio: '/asm-studio',
  war_room: '/war-room',
}

const ROUTE_VIEWS: Record<string, View> = Object.fromEntries(
  Object.entries(VIEW_ROUTES).map(([view, path]) => [path, view as View]),
)

const viewFromPath = (pathname: string): View | null =>
  ROUTE_VIEWS[pathname.replace(/\/+$/, '') || '/'] ?? null

interface ThemeContextType {
  activeTheme: Theme
  currentView: View
  showThemeDrawer: boolean
  glow: number
  density: Density
  cornerRadius: CornerRadius
  bgGrid: 'dots' | 'blueprint' | 'solid'
  scanlines: boolean
  toggleThemeDrawer: () => void
  toggleTheme: (t: Theme) => void
  switchView: (v: View) => void
  setGlow: (v: number) => void
  setDensity: (v: Density) => void
  setCornerRadius: (v: CornerRadius) => void
  setBgGrid: (v: 'dots' | 'blueprint' | 'solid') => void
  setScanlines: (v: boolean) => void
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined)

const THEME_CONFIG: Record<Theme, { label: string; color: string; desc: string }> = {
  obsidian: { label: 'Vortex Obsidian', color: '#00f0ff', desc: 'Cyber Quantum' },
  aurum: { label: 'Aurum XAU', color: '#f59e0b', desc: 'Sovereign Gold Terminal' },
  lapis: { label: 'Lapis Vault', color: '#3b82f6', desc: 'Royal Lazurite' },
  arch: { label: 'Arch Matrix', color: '#10b981', desc: 'Kernel Root' },
  vault: { label: 'Vault Alabaster', color: '#1e3a8a', desc: 'High-Contrast Daylight' }
}

export const ThemeProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [activeTheme, setActiveTheme] = useState<Theme>(() => {
    return (localStorage.getItem('vortex-theme') as Theme) || 'obsidian'
  })
  const [currentView, setCurrentView] = useState<View>(() => {
    // URL wins over localStorage on first load: /hexinspector renders the inspector.
    const fromPath = viewFromPath(window.location.pathname)
    if (fromPath) return fromPath
    return (localStorage.getItem('vortex-view') as View) || 'command'
  })
  const [showThemeDrawer, setShowThemeDrawer] = useState(false)
  const [glow, setGlow] = useState(() => Number(localStorage.getItem('vortex-glow') || 50))
  const [density, setDensity] = useState<Density>(() => {
    return (localStorage.getItem('vortex-density') as Density) || 'comfortable'
  })
  const [cornerRadius, setCornerRadius] = useState<CornerRadius>(6)
  const [bgGrid, setBgGrid] = useState<'dots' | 'blueprint' | 'solid'>(() => {
    return (localStorage.getItem('vortex-grid') as 'dots' | 'blueprint' | 'solid') || 'dots'
  })
  const [scanlines, setScanlines] = useState(() => {
    return localStorage.getItem('vortex-scanlines') === 'true'
  })

  // Persist settings
  useEffect(() => {
    localStorage.setItem('vortex-theme', activeTheme)
    document.documentElement.setAttribute('data-theme', activeTheme)
    const glowVar = glow / 100
    document.documentElement.style.setProperty('--glow-strength', String(glowVar))
    document.documentElement.style.setProperty('--radius-ui', `${cornerRadius}px`)
  }, [activeTheme, glow, cornerRadius])

  useEffect(() => localStorage.setItem('vortex-view', currentView), [currentView])
  useEffect(() => localStorage.setItem('vortex-glow', String(glow)), [glow])
  useEffect(() => localStorage.setItem('vortex-density', density), [density])
  useEffect(() => localStorage.setItem('vortex-grid', bgGrid), [bgGrid])
  useEffect(() => localStorage.setItem('vortex-scanlines', String(scanlines)), [scanlines])

  // pushState routing: the URL always mirrors the active view
  const switchView = React.useCallback((v: View) => {
    setCurrentView(v)
    const path = VIEW_ROUTES[v]
    if (window.location.pathname !== path) {
      window.history.pushState({ view: v }, '', path)
    }
  }, [])

  // Back/forward buttons resolve the view from the restored pathname
  useEffect(() => {
    const onPop = () => {
      setCurrentView(viewFromPath(window.location.pathname) ?? 'command')
    }
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  }, [])

  // Keyboard shortcuts 1-9 (follows DockNav hotkeys)
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key >= '1' && e.key <= '9') {
        const views: View[] = ['command', 'hex', 'security', 'lab', 'vault', 'zk_matrix', 'tensor_v6', 'asm_studio', 'war_room']
        const target = views[parseInt(e.key) - 1]
        if (target) {
          e.preventDefault()
          switchView(target)
        }
      }
      if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault()
        setShowThemeDrawer(true)
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [switchView])

  return (
    <ThemeContext.Provider
      value={{
        activeTheme,
        currentView,
        showThemeDrawer,
        glow,
        density,
        cornerRadius,
        bgGrid,
        scanlines,
        toggleThemeDrawer: () => setShowThemeDrawer(!showThemeDrawer),
        toggleTheme: setActiveTheme,
        switchView,
        setGlow,
        setDensity,
        setCornerRadius,
        setBgGrid,
        setScanlines
      }}
    >
      {children}
    </ThemeContext.Provider>
  )
}

export const useTheme = () => {
  const ctx = useContext(ThemeContext)
  if (!ctx) throw new Error('useTheme must be used within ThemeProvider')
  return ctx
}

export const THEME_CONFIG_EXPORT = THEME_CONFIG
