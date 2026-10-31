import { useState, useEffect } from 'react'
import { Shield, Flame, Lock, Eye, EyeOff, Cpu, Key, AlertTriangle } from 'lucide-react'
import { useWorkspace } from '../../contexts/WorkspaceContext'

interface VaultMemoryStats {
  ok: boolean
  arena_size: number
  page_size: number
  pool_size: number
  void_pages: number
  locked_pages: number
  burned_pages: number
  states: string[]
  hardware_uuid_seed: number
  mlock_active: boolean
  bound_cpu: number
  realtime_priority: number
  debugger_detected: boolean
  lock_step_cycles: number
}

interface VaultActionResult {
  ok: boolean
  hash?: string
  result?: string
  error?: string
}

export default function VaultPanel() {
  const { } = useWorkspace()
  const [stats, setStats] = useState<VaultMemoryStats | null>(null)
  const [actionResult, setActionResult] = useState<VaultActionResult | null>(null)
  const [payload, setPayload] = useState('')
  const [showSecret, setShowSecret] = useState(false)

  const fetchStats = async () => {
    try {
      const res = await fetch('/api/vault/memory')
      const data = await res.json()
      setStats(data)
    } catch (e) {
      console.error('Failed to fetch vault stats:', e)
    }
  }

  useEffect(() => {
    fetchStats()
    const interval = setInterval(fetchStats, 5000)
    return () => clearInterval(interval)
  }, [])

  const handleAction = async (action: string) => {
    try {
      const body: any = { action }
      if (action === 'commit' && payload) {
        body.payload = payload
      }
      const res = await fetch('/api/vault/action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const data = await res.json()
      setActionResult(data)
      fetchStats()
    } catch (e) {
      setActionResult({ ok: false, error: String(e) })
    }
  }

  const stateColors: Record<string, string> = {
    VOID: '#1a1a2e',
    LOCKED: '#00ff88',
    BURNED: '#ff4444',
  }

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <header className="p-4 border-b border-[var(--border-subtle)] panel-specular">
        <div className="flex items-center gap-3">
          <Shield className="w-5 h-5 text-[var(--accent-primary)]" />
          <div>
            <h1 className="font-mono text-sm text-[var(--accent-primary)]">VAULT MEMORY CORE</h1>
            <p className="text-[10px] text-[var(--text-muted)] mt-1">
              PageState transitions: VOID(0) → LOCKED(1) → BURNED(2) • Hardware UUID DNA Binding
            </p>
          </div>
        </div>
      </header>

      <div className="flex-1 overflow-auto p-4 space-y-4">
        <div className="panel grid grid-cols-4 gap-4">
          <StatCard
            label="Arena Size"
            value={`${(stats?.arena_size ?? 0 / 1024 / 1024).toFixed(1)} MB`}
            icon={Cpu}
          />
          <StatCard
            label="Pool Size"
            value={stats?.pool_size.toString() ?? '0'}
            icon={Lock}
          />
          <StatCard
            label="mlock Active"
            value={stats?.mlock_active ? 'YES' : 'NO'}
            icon={Key}
            color={stats?.mlock_active ? 'green' : 'red'}
          />
          <StatCard
            label="Debugger"
            value={stats?.debugger_detected ? 'DETECTED' : 'CLEAR'}
            icon={EyeOff}
            color={stats?.debugger_detected ? 'red' : 'green'}
          />
        </div>

        <div className="panel p-4">
          <h3 className="font-mono text-xs text-[var(--accent-primary)] mb-3">PAGE STATE DISTRIBUTION</h3>
          <div className="grid grid-cols-3 gap-4">
            <PageStateCard label="VOID" value={stats?.void_pages ?? 0} percentage={((stats?.void_pages ?? 0) / (stats?.pool_size ?? 1) * 100).toFixed(1)} color="#64748b" />
            <PageStateCard label="LOCKED" value={stats?.locked_pages ?? 0} percentage={((stats?.locked_pages ?? 0) / (stats?.pool_size ?? 1) * 100).toFixed(1)} color="#00ff88" />
            <PageStateCard label="BURNED" value={stats?.burned_pages ?? 0} percentage={((stats?.burned_pages ?? 0) / (stats?.pool_size ?? 1) * 100).toFixed(1)} color="#ff4444" />
          </div>
        </div>

        <div className="panel p-4">
          <h3 className="font-mono text-xs text-[var(--accent-primary)] mb-3">PAGE MATRIX (First 256 Pages)</h3>
          <div className="grid grid-cols-16 gap-1">
            {(stats?.states ?? []).slice(0, 256).map((state, i) => (
              <div
                key={i}
                className="w-3 h-3 rounded-sm"
                style={{ backgroundColor: stateColors[state] || '#1a1a2e' }}
                title={`Page ${i}: ${state}`}
              />
            ))}
          </div>
        </div>

        <div className="panel p-4">
          <h3 className="font-mono text-xs text-[var(--accent-primary)] mb-3">HARDWARE DNA BINDING</h3>
          <div className="grid grid-cols-2 gap-4">
            {[
              { label: 'Hardware UUID Seed', value: stats ? `0x${stats.hardware_uuid_seed.toString(16).padStart(16, '0')}` : 'N/A' },
              { label: 'Lock-Step Cycles', value: String(stats?.lock_step_cycles ?? 0) },
              { label: 'Bound CPU', value: stats?.bound_cpu !== undefined && stats.bound_cpu >= 0 ? `Core ${stats.bound_cpu}` : 'None' },
              { label: 'RT Priority', value: stats?.realtime_priority !== undefined && stats.realtime_priority >= 0 ? `${stats.realtime_priority}` : 'Normal' },
            ].map((item) => (
              <div key={item.label}>
                <label className="font-mono text-[10px] text-[var(--text-muted)]">{item.label}</label>
                <div className="font-mono text-[11px] text-[var(--text-primary)] mt-1">{item.value}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="panel p-4">
          <h3 className="font-mono text-xs text-[var(--accent-primary)] mb-3">VAULT ACTIONS</h3>
          <div className="space-y-3">
            <div>
              <label className="font-mono text-[10px] text-[var(--text-muted)] block mb-1">SECRET PAYLOAD</label>
              <div className="relative">
                <input
                  type={showSecret ? 'text' : 'password'}
                  value={payload}
                  onChange={(e) => setPayload(e.target.value)}
                  placeholder="Enter secret to commit..."
                  className="input-field w-full text-[11px] pr-10"
                />
                <button
                  onClick={() => setShowSecret(!showSecret)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-[var(--text-muted)] hover:text-[var(--accent-primary)]"
                >
                  {showSecret ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>
            <div className="flex gap-2">
              <button onClick={() => handleAction('commit')} className="btn-primary text-xs px-4 py-2 flex items-center gap-2"><Lock className="w-3 h-3" /> COMMIT & LOCK</button>
              <button onClick={() => handleAction('consume')} className="btn-secondary text-xs px-4 py-2 flex items-center gap-2"><Flame className="w-3 h-3 text-red-500" /> CONSUME & BURN</button>
              <button onClick={() => handleAction('emergency_burn')} className="btn-danger text-xs px-4 py-2 flex items-center gap-2"><AlertTriangle className="w-3 h-3" /> EMERGENCY BURN ALL</button>
            </div>
          </div>
        </div>

        {actionResult && (
          <div className={`panel p-4 ${actionResult.ok ? 'border-[var(--accent-primary)]' : 'border-red-500'}`}>
            <h3 className="font-mono text-xs text-[var(--accent-primary)] mb-2">{actionResult.ok ? '✓ ACTION SUCCESSFUL' : '✗ ACTION FAILED'}</h3>
            {actionResult.hash && (
              <div>
                <label className="font-mono text-[10px] text-[var(--text-muted)]">Hash (32 bytes)</label>
                <div className="font-mono text-[10px] text-[var(--text-primary)] break-all mt-1">0x{actionResult.hash}</div>
              </div>
            )}
            {actionResult.result && <div className="mt-2 font-mono text-[11px] text-[var(--text-primary)]">{actionResult.result}</div>}
            {actionResult.error && <div className="mt-2 font-mono text-[11px] text-red-500">{actionResult.error}</div>}
          </div>
        )}
      </div>
    </div>
  )
}

function StatCard({ label, value, icon: Icon, color = 'primary' }: { label: string; value: string; icon: any; color?: string }) {
  const colorMap: Record<string, string> = { primary: 'text-[var(--accent-primary)]', green: 'text-green-500', red: 'text-red-500' }
  return (
    <div className="bg-[var(--bg-primary)] rounded p-3 border border-[var(--border-subtle)]">
      <div className="flex items-center gap-2 mb-2">
        <Icon className={`w-4 h-4 ${colorMap[color] || colorMap.primary}`} />
        <span className="font-mono text-[10px] text-[var(--text-muted)]">{label}</span>
      </div>
      <div className={`font-mono text-xl ${colorMap[color] || colorMap.primary}`}>{value}</div>
    </div>
  )
}

function PageStateCard({ label, value, percentage, color }: { label: string; value: number; percentage: string; color: string }) {
  return (
    <div className="bg-[var(--bg-primary)] rounded p-3 border border-[var(--border-subtle)]">
      <div className="flex items-center gap-2 mb-2">
        <div className="w-3 h-3 rounded-full" style={{ backgroundColor: color }}></div>
        <span className="font-mono text-xs" style={{ color }}>{label}</span>
      </div>
      <div className="text-2xl font-mono" style={{ color }}>{value}</div>
      <div className="text-[10px] text-[var(--text-muted)] mt-1">{percentage}%</div>
    </div>
  )
}
