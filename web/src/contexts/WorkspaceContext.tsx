import React, { createContext, useContext, useState, useEffect, useRef, useCallback, ReactNode } from 'react'
import { useRpcHost } from './RpcHostContext'

export interface StatusResponse {
  chain_height: number
  tip_block_index: number
  ledger_bytes: number
  frame_size: number
  max_tx_per_block: number
  total_supply_atomics: string
  total_supply_vx: string
  tracked_accounts_count: number
  tip_hash_hex: string
  crypto_engine: string
  storage_engine: string
  memory_locked?: boolean
  simd_isa?: string
}

export interface Block {
  height: number
  timestamp: number
  tx_count: number
  hash: string
  magic_hex: string
  block_hash_hex: string
  prev_block_hash_hex: string
  merkle_root_hex: string
  attractor_coords: { x_hex: string; y_hex: string; z_hex: string }
  memory_layout: { header_bytes: number; tx_used_bytes: number; tx_free_bytes: number; tail_reserved_bytes: number; utilization_pct: number }
  raw_header_hex: string
  transactions: Transaction[]
}

export interface Transaction {
  index: number
  sender_nfa: string
  receiver_nfa: string
  amount_atomics: string
  amount_vx: string
  cocoon_proof_hex: string
  proof_valid: boolean
  raw_tx_hex: string
}

export interface Account {
  address: string
  payload_42: string
  label: string
  balance_atomics: string
  balance_vx: string
}

interface CryptoLabResult {
  seed: string
  rounds: number
  execution_time_ms: number
  coordinates: { x_hex: string; y_hex: string; z_hex: string }
  address_nfa: string
  address_ofa: string
  wif: {
    record: string
    compact: string
    compressed: string
    ghost: string
  }
  sac?: SacRoundData[]
}

interface SacRoundData {
  round: number
  bit_distance: number
  percentage: number
}

interface WorkspaceContextType {
  status: StatusResponse | null
  blocks: Block[]
  accounts: Account[]
  selectedBlock: Block | null
  selectedTx: Transaction | null
  cryptoLab: CryptoLabResult | null
  auditResult: any | null
  isLoading: boolean
  connectionStatus: 'connecting' | 'online' | 'offline'
  lastRpcTime: number | null
  refreshAll: () => Promise<void>
  fetchStatus: () => Promise<void>
  fetchBlocks: () => Promise<void>
  fetchAccounts: () => Promise<void>
  fetchBlock: (height: number) => Promise<void>
  executeTransfer: (sender: string, receiver: string, amount: number) => Promise<any>
  executeAudit: (type: string) => Promise<any>
  executePqSign: (opts?: { amount_vx?: number; fee?: number; nonce?: number; seed_hex?: string }) => Promise<any>
  executePqVerify: () => Promise<any>
  executeCryptoLab: (seed: string, rounds: number, sac: boolean) => Promise<void>
  setSelectedBlock: (b: Block | null) => void
  setSelectedTx: (t: Transaction | null) => void
  rpcLog: string[]
  addRpcLog: (msg: string) => void
}

const WorkspaceContext = createContext<WorkspaceContextType | undefined>(undefined)

// SSE Event types we handle
const SSE_EVENTS = ['block_sealed', 'mempool_updated', 'miner_tick', 'security_verdict'] as const

export const WorkspaceProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const { resolveUrl } = useRpcHost()

  const [status, setStatus] = useState<StatusResponse | null>(null)
  const [blocks, setBlocks] = useState<Block[]>([])
  const [accounts, setAccounts] = useState<Account[]>([])
  const [selectedBlock, setSelectedBlock] = useState<Block | null>(null)
  const [selectedTx, setSelectedTx] = useState<Transaction | null>(null)
  const [cryptoLab, setCryptoLab] = useState<CryptoLabResult | null>(null)
  const [auditResult, setAuditResult] = useState<any | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [connectionStatus, setConnectionStatus] = useState<'connecting' | 'online' | 'offline'>('connecting')
  const [lastRpcTime, setLastRpcTime] = useState<number | null>(null)
  const [rpcLog, setRpcLog] = useState<string[]>([])

  // SSE connection state
  const eventSourceRef = useRef<EventSource | null>(null)
  const sseReconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const isSseConnectingRef = useRef(false)

  // Request deduplication state - In-Flight Promise Coalescing
  const inFlightRequests = useRef<Map<string, Promise<any>>>(new Map())
  const abortControllersRef = useRef<Map<string, AbortController>>(new Map())
  const lastDataRef = useRef<{
    status: StatusResponse | null
    blocks: Block[]
    accounts: Account[]
  }>({ status: null, blocks: [], accounts: [] })
  const dirtyFlagsRef = useRef({ status: false, blocks: false, accounts: false })

  const addRpcLog = useCallback((msg: string) => {
    setRpcLog(prev => {
      const next = [...prev, `[${new Date().toLocaleTimeString()}.${Date.now() % 1000}] ${msg}`]
      return next.slice(-100)
    })
  }, [])

  // Deep equality check for dirty state detection
  const isEqual = useCallback(<T,>(a: T, b: T): boolean => {
    return JSON.stringify(a) === JSON.stringify(b)
  }, [])

  // Check if data has changed
  const checkAndMarkDirty = useCallback(<T,>(key: 'status' | 'blocks' | 'accounts', newData: T): boolean => {
    const oldData = (lastDataRef.current as Record<string, unknown>)[key]
    const changed = !isEqual(oldData, newData)
    if (changed) {
      dirtyFlagsRef.current[key] = true
      ;(lastDataRef.current as Record<string, unknown>)[key] = newData
    }
    return changed
  }, [isEqual])

  // API call with In-Flight Promise Coalescing (replaces AbortController dedupe)
  const apiCall = useCallback(async (endpoint: string, options?: RequestInit): Promise<any> => {
    const method = options?.method || 'GET'
    const key = `${method} ${endpoint}`

    // For GET requests, coalesce in-flight promises
    if (method === 'GET') {
      const existingPromise = inFlightRequests.current.get(key)
      if (existingPromise) {
        addRpcLog(`COALESCE ${method} ${endpoint}`)
        return existingPromise
      }
    }

    const start = performance.now()
    const url = resolveUrl(endpoint)
    const promise = (async () => {
      try {
        const res = await fetch(url, {
          headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
          ...options
        })

        const elapsed = performance.now() - start
        if (!res.ok) {
          const err = await res.json().catch(() => ({ error: res.statusText }))
          throw new Error(err.error || `HTTP ${res.status}`)
        }

        const data = await res.json()
        addRpcLog(`${method} ${endpoint} -> 200 OK (${elapsed.toFixed(2)} ms)`)
        setConnectionStatus('online')
        return data
      } catch (e: any) {
        const elapsed = performance.now() - start
        addRpcLog(`${method} ${endpoint} -> ERROR (${elapsed.toFixed(2)} ms): ${e.message}`)
        setConnectionStatus('offline')
        throw e
      } finally {
        inFlightRequests.current.delete(key)
      }
    })()

    if (method === 'GET') {
      inFlightRequests.current.set(key, promise)
    }

    return promise
  }, [addRpcLog, resolveUrl])

  const fetchStatus = useCallback(async () => {
    try {
      const data = await apiCall('/status')
      // Only update state if data actually changed
      if (checkAndMarkDirty('status', data)) {
        setStatus(data)
        setLastRpcTime(performance.now())
      }
    } catch (e) {
      // Error already logged in apiCall
    }
  }, [apiCall, checkAndMarkDirty])

  const fetchBlocks = useCallback(async () => {
    try {
      const data = await apiCall('/blocks')
      if (checkAndMarkDirty('blocks', data.blocks)) {
        setBlocks(data.blocks)
      }
    } catch (e) {
      // Error already logged
    }
  }, [apiCall, checkAndMarkDirty])

  const fetchAccounts = useCallback(async () => {
    try {
      const data = await apiCall('/accounts')
      if (checkAndMarkDirty('accounts', data.accounts)) {
        setAccounts(data.accounts)
      }
    } catch (e) {
      // Error already logged
    }
  }, [apiCall, checkAndMarkDirty])

  const fetchBlock = useCallback(async (height: number) => {
    // Blocks endpoint already returns all blocks
    if (!blocks.find(b => b.height === height)) {
      await fetchBlocks()
    }
  }, [blocks, fetchBlocks])

  const executeTransfer = useCallback(async (sender: string, receiver: string, amount: number) => {
    const data = await apiCall('/transfer', {
      method: 'POST',
      body: JSON.stringify({ sender, receiver, amount_vx: amount, include_miner_reward: false })
    })
    // Invalidate cache after mutation
    dirtyFlagsRef.current = { status: true, blocks: true, accounts: true }
    await refreshAll()
    return data
  }, [apiCall])

  const executeAudit = useCallback(async (type: string) => {
    const data = await apiCall('/security/audit', {
      method: 'POST',
      body: JSON.stringify({ attack_type: type })
    })
    setAuditResult(data)
    return data
  }, [apiCall])

  const executePqSign = useCallback(async (opts?: { amount_vx?: number; fee?: number; nonce?: number; seed_hex?: string }) => {
    return apiCall('/crypto/pq_sign', {
      method: 'POST',
      body: JSON.stringify(opts ?? {})
    })
  }, [apiCall])

  const executePqVerify = useCallback(async () => {
    return apiCall('/crypto/pq_verify', { method: 'POST', body: JSON.stringify({}) })
  }, [apiCall])

  const executeCryptoLab = useCallback(async (seed: string, rounds: number, sac: boolean) => {
    const data = await apiCall('/crypto/lab', {
      method: 'POST',
      body: JSON.stringify({ seed, rounds, use_secure_crt: true, sac_test: sac })
    })
    setCryptoLab(data)
  }, [apiCall])

  const refreshAll = useCallback(async () => {
    setIsLoading(true)
    try {
      // Use Promise.allSettled to not fail all if one fails
      await Promise.allSettled([fetchStatus(), fetchBlocks(), fetchAccounts()])
    } finally {
      setIsLoading(false)
    }
  }, [fetchStatus, fetchBlocks, fetchAccounts])

  // SSE Connection management
  const connectSSE = useCallback(() => {
    if (isSseConnectingRef.current || eventSourceRef.current?.readyState === EventSource.OPEN) {
      return
    }

    isSseConnectingRef.current = true
    addRpcLog('SSE: Connecting to /api/events...')

    try {
      const es = new EventSource(resolveUrl('/api/events'))
      eventSourceRef.current = es

      es.onopen = () => {
        isSseConnectingRef.current = false
        addRpcLog('SSE: Connected')
        setConnectionStatus('online')
      }

      es.onerror = () => {
        isSseConnectingRef.current = false
        addRpcLog('SSE: Connection error, will retry in 3s')
        setConnectionStatus('offline')
        es.close()
        eventSourceRef.current = null

        // Schedule reconnect with 3s fallback
        if (sseReconnectTimeoutRef.current) clearTimeout(sseReconnectTimeoutRef.current)
        sseReconnectTimeoutRef.current = setTimeout(() => {
          connectSSE()
        }, 3000)
      }

      // Handle specific event types
      SSE_EVENTS.forEach(eventName => {
        es.addEventListener(eventName, (e: MessageEvent) => {
          try {
            JSON.parse(e.data)
            addRpcLog(`SSE: ${eventName} received`)

            switch (eventName) {
              case 'block_sealed':
                dirtyFlagsRef.current = { status: true, blocks: true, accounts: true }
                refreshAll()
                break
              case 'mempool_updated':
                // Will be implemented in Phase 7
                break
              case 'miner_tick':
                // Will be implemented in Phase 8
                break
              case 'security_verdict':
                // Will be implemented in Phase 8
                break
            }
          } catch (parseErr) {
            addRpcLog(`SSE: Parse error for ${eventName}`)
          }
        })
      })

      // Fallback: generic message handler
      es.onmessage = (e: MessageEvent) => {
        // Ignore comment lines (heartbeats)
        if (e.data.startsWith(':')) return
        addRpcLog(`SSE: message: ${e.data.slice(0, 80)}`)
      }

    } catch (err) {
      isSseConnectingRef.current = false
      addRpcLog(`SSE: Failed to connect: ${err}`)
      // Schedule reconnect
      if (sseReconnectTimeoutRef.current) clearTimeout(sseReconnectTimeoutRef.current)
      sseReconnectTimeoutRef.current = setTimeout(() => {
        connectSSE()
      }, 3000)
    }
  }, [addRpcLog, refreshAll, resolveUrl])

  // Initial load and SSE connection
  useEffect(() => {
    refreshAll()
    connectSSE()

    // 3-second fallback poll if SSE disconnects
    const fallbackInterval = setInterval(() => {
      if (eventSourceRef.current?.readyState !== EventSource.OPEN) {
        addRpcLog('FALLBACK POLL: SSE disconnected, polling...')
        refreshAll()
      }
    }, 3000)

    return () => {
      clearInterval(fallbackInterval)
      if (sseReconnectTimeoutRef.current) clearTimeout(sseReconnectTimeoutRef.current)
      if (eventSourceRef.current) {
        eventSourceRef.current.close()
        eventSourceRef.current = null
      }
      // Clear in-flight promises
      inFlightRequests.current.clear()
      abortControllersRef.current.clear()
    }
  }, [refreshAll, connectSSE, addRpcLog])

  return (
    <WorkspaceContext.Provider
      value={{
        status, blocks, accounts, selectedBlock, selectedTx, cryptoLab, auditResult,
        isLoading, connectionStatus, lastRpcTime,
        refreshAll, fetchStatus, fetchBlocks, fetchAccounts, fetchBlock,
        executeTransfer, executeAudit, executePqSign, executePqVerify, executeCryptoLab,
        setSelectedBlock, setSelectedTx,
        rpcLog, addRpcLog
      }}
    >
      {children}
    </WorkspaceContext.Provider>
  )
}

export const useWorkspace = () => {
  const ctx = useContext(WorkspaceContext)
  if (!ctx) throw new Error('useWorkspace must be used within WorkspaceProvider')
  return ctx
}