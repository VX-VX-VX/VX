import { createContext, useContext, useEffect, useState, ReactNode } from 'react'

export interface RpcHostPreset {
  id: string
  label: string
  url: string
  port: number
}

const PRESETS: RpcHostPreset[] = [
  { id: 'proxy', label: 'Relative Proxy', url: '/api', port: 0 },
  { id: 'localhost', label: 'Localhost', url: 'http://localhost:8088', port: 8088 },
]

interface RpcHostContextType {
  rpcHost: RpcHostPreset
  presets: RpcHostPreset[]
  customUrl: string
  isCustomOpen: boolean
  setCustomUrl: (v: string) => void
  selectHost: (id: string) => void
  toggleCustom: () => void
  resolveUrl: (path: string) => string
}

const RpcHostContext = createContext<RpcHostContextType | undefined>(undefined)

export function RpcHostProvider({ children }: { children: ReactNode }) {
  // Migrate old port 8080 to 8088 on initialization
  const [hostId, setHostId] = useState(() => {
    const saved = localStorage.getItem('vx_rpc_host') || 'proxy'
    if (saved === 'custom') {
      const url = localStorage.getItem('vx_rpc_custom') || ''
      if (url.includes(':8080')) {
        const migrated = url.replace(':8080', ':8088')
        localStorage.setItem('vx_rpc_custom', migrated)
      }
    }
    return saved
  })
  const [customUrl, setCustomUrl] = useState(() => localStorage.getItem('vx_rpc_custom') || '')
  const [isCustomOpen, setIsCustomOpen] = useState(false)

  const preset = PRESETS.find(p => p.id === hostId) || PRESETS[0]
  const effectiveUrl = hostId === 'custom' ? customUrl : preset.url

  useEffect(() => {
    localStorage.setItem('vx_rpc_host', hostId)
  }, [hostId])

  // Auto-migrate old port 8080 to 8088 on first read
  useEffect(() => {
    if (customUrl && customUrl.includes(':8080')) {
      const migrated = customUrl.replace(':8080', ':8088')
      setCustomUrl(migrated)
    }
  }, [customUrl])

  useEffect(() => {
    localStorage.setItem('vx_rpc_custom', customUrl)
  }, [customUrl])

  const resolveUrl = (path: string): string => {
    // Always prepend /api/ if path doesn't already have it
    let cleanPath = path
    if (!cleanPath.startsWith('/api/')) {
      cleanPath = cleanPath.startsWith('/')
        ? `/api${cleanPath}`
        : `/api/${cleanPath}`
    }

    if (path.startsWith('http')) return path

    // Auto-replace old port 8080 with /api or 8088
    let effective = effectiveUrl
    if (effective.includes(':8080')) {
      effective = effective.replace(':8080', ':8088')
      // Update stored value to prevent stale port from persisting
      if (hostId === 'custom') {
        setCustomUrl(effective)
      }
    }

    if (effective === '/api') return cleanPath

    // effectiveUrl is a full base URL like http://localhost:8088
    // (or a user-configured custom URL via the Custom host preset).
    const baseHost = effective.replace(/\/+$/, '')      // strip trailing slashes
    const cleanBase = baseHost.replace(/\/api$/, '')      // remove trailing /api
    return cleanBase + cleanPath
  }

  const selectHost = (id: string) => {
    setHostId(id)
    if (id === 'custom' && customUrl) {
      // already set
    }
  }

  return (
    <RpcHostContext.Provider value={{
      rpcHost: preset,
      presets: PRESETS,
      customUrl,
      isCustomOpen,
      setCustomUrl,
      selectHost,
      toggleCustom: () => setIsCustomOpen(v => !v),
      resolveUrl
    }}>
      {children}
    </RpcHostContext.Provider>
  )
}

export const useRpcHost = () => {
  const ctx = useContext(RpcHostContext)
  if (!ctx) throw new Error('useRpcHost must be used within RpcHostProvider')
  return ctx
}