import { createContext, useContext, useEffect, useState, useCallback, ReactNode } from 'react'

// RPC access-token workflow (v0.0.7).
//
// The node gates mutating endpoints (and several heavy GETs) behind a
// Bearer token (VX_RPC_TOKEN on the node side). The console therefore
// needs to attach "Authorization: Bearer <token>" to every /api call.
//
// Storage choice: localStorage is a deliberate tradeoff for a local
// operator tool — it survives reloads, never leaves the browser, and is
// never written to logs (the value is never passed to addRpcLog).
// It is NOT shared across devices and is cleared by the user explicitly.

const TOKEN_KEY = 'vx_rpc_token'

interface TokenContextType {
  hasToken: boolean
  token: string
  setToken: (t: string) => void
  clearToken: () => void
  authHeaders: () => Record<string, string>
  authRequired: boolean
  setAuthRequired: (v: boolean) => void
  vxFetch: (url: string, init?: RequestInit) => Promise<Response>
}

const TokenContext = createContext<TokenContextType | undefined>(undefined)

export function TokenProvider({ children }: { children: ReactNode }) {
  const [token, setTokenState] = useState<string>(() => {
    try {
      return localStorage.getItem(TOKEN_KEY) || ''
    } catch {
      return '' // private window / blocked storage: still fully usable, just unauthenticated
    }
  })
  const [authRequired, setAuthRequired] = useState(false)

  useEffect(() => {
    try {
      if (token) localStorage.setItem(TOKEN_KEY, token)
      else localStorage.removeItem(TOKEN_KEY)
    } catch {
      // storage unavailable: keep the in-memory token for this session
    }
  }, [token])

  const setToken = useCallback((t: string) => setTokenState(t.trim()), [])
  const clearToken = useCallback(() => {
    setTokenState('')
    setAuthRequired(false)
  }, [])

  const authHeaders = useCallback(
    (): Record<string, string> => (token ? { Authorization: `Bearer ${token}` } : {}),
    [token]
  )

  // Hook-shaped fetch wrapper so views that call fetch() directly still
  // send the token. Merges over caller headers; never logs the token.
  const vxFetch = useCallback(
    (url: string, init?: RequestInit): Promise<Response> =>
      fetch(url, {
        ...init,
        headers: { ...authHeaders(), ...(init?.headers as Record<string, string> | undefined) },
      }),
    [authHeaders]
  )

  return (
    <TokenContext.Provider
      value={{ hasToken: !!token, token, setToken, clearToken, authHeaders, authRequired, setAuthRequired, vxFetch }}
    >
      {children}
    </TokenContext.Provider>
  )
}

export function useToken(): TokenContextType {
  const ctx = useContext(TokenContext)
  if (!ctx) throw new Error('useToken must be used within TokenProvider')
  return ctx
}
