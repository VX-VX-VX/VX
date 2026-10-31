import { useState } from 'react'
import { RefreshCw, Check, X, Shield } from 'lucide-react'

interface KeyTier {
  tier_index: number
  tier_name: string
  key_data: string
  can_sign: boolean
  can_view_inputs: boolean
  can_view_outputs: boolean
  can_view_balance: boolean
}

interface ShamirShard {
  x: number
  y: string
}

interface ZKDeriveResult {
  ok: boolean
  keys?: KeyTier[]
  error?: string
}

interface ShamirResult {
  ok: boolean
  shards?: ShamirShard[]
  recovered?: string
  recovery_successful?: boolean
  error?: string
}

interface PoLResult {
  ok: boolean
  proof?: {
    valid: boolean
    commitment: string
    proof_hash: string
    timestamp: number
  }
  verification?: {
    valid: boolean
    within_time_window: boolean
  }
  error?: string
}

export default function ZKMatrixPanel() {
  const [deriveResult, setDeriveResult] = useState<ZKDeriveResult | null>(null)
  const [shamirResult, setShamirResult] = useState<ShamirResult | null>(null)
  const [polResult, setPolResult] = useState<PoLResult | null>(null)
  const [selectedShards, setSelectedShards] = useState<Set<number>>(new Set([0, 1]))
  const [seedInput, setSeedInput] = useState('')
  const [activeTab, setActiveTab] = useState<'derive' | 'shamir' | 'pol'>('derive')

  const deriveKeys = async () => {
    try {
      const body: any = {}
      if (seedInput) body.seed_hex = seedInput
      const res = await fetch('/api/zk/derive_matrix', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const data = await res.json()
      setDeriveResult(data)
    } catch (e) {
      setDeriveResult({ ok: false, error: String(e) })
    }
  }

  const recoverShamir = async () => {
    try {
      const shards: number[] = []
      selectedShards.forEach(i => shards.push(i))
      const res = await fetch('/api/zk/recover_shamir', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ shards }),
      })
      const data = await res.json()
      setShamirResult(data)
    } catch (e) {
      setShamirResult({ ok: false, error: String(e) })
    }
  }

  const generatePoL = async () => {
    try {
      const res = await fetch('/api/zk/proof_of_life', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      })
      const data = await res.json()
      setPolResult(data)
    } catch (e) {
      setPolResult({ ok: false, error: String(e) })
    }
  }

  const toggleShard = (idx: number) => {
    setSelectedShards(prev => {
      const next = new Set(prev)
      if (next.has(idx)) {
        if (next.size > 3) next.delete(idx)
      } else {
        next.add(idx)
      }
      return next
    })
  }

  const tierColors = ['#00ff88', '#00d4ff', '#ff6b35', '#a855f7', '#facc15', '#ef4444', '#22d3ee']

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <header className="p-4 border-b border-[var(--border-subtle)] panel-specular">
        <div className="flex items-center gap-3">
          <Shield className="w-5 h-5 text-[var(--accent-primary)]" />
          <div>
            <h1 className="font-mono text-sm text-[var(--accent-primary)]">ZK KEY MATRIX</h1>
            <p className="text-[10px] text-[var(--text-muted)] mt-1">
              Fractal Chaos Key Derivation • GF(2^8) Shamir Secret Sharing • Proof-of-Life Verification
            </p>
          </div>
        </div>
      </header>

      <div className="flex-1 overflow-auto p-4 space-y-4">
        {/* Tabs */}
        <div className="flex gap-1 border-b border-[var(--border-subtle)]">
          {(['derive', 'shamir', 'pol'] as const).map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-2 font-mono text-xs ${
                activeTab === tab
                  ? 'text-[var(--accent-primary)] border-b-2 border-[var(--accent-primary)]'
                  : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
              }`}
            >
              {tab === 'derive' ? 'KEY DERIVATION' : tab === 'shamir' ? 'SHAMIR SECRET' : 'PROOF OF LIFE'}
            </button>
          ))}
        </div>

        {/* Key Derivation Tab */}
        {activeTab === 'derive' && (
          <>
            <div className="panel p-4">
              <div className="flex items-center gap-3 mb-3">
                <h3 className="font-mono text-xs text-[var(--accent-primary)]">DERIVE 7 UNIQUE KEYS</h3>
                <input
                  type="text"
                  value={seedInput}
                  onChange={e => setSeedInput(e.target.value)}
                  placeholder="Optional seed hex (32 bytes)..."
                  className="input-field text-[11px] w-64"
                />
                <button onClick={deriveKeys} className="btn-primary text-xs px-3 py-1 flex items-center gap-1">
                  <RefreshCw className="w-3 h-3" /> DERIVE
                </button>
              </div>
            </div>

            {deriveResult && (
              <div className="space-y-2">
                {deriveResult.ok && deriveResult.keys?.map((tier, i) => (
                  <div key={i} className="panel p-3 flex items-center gap-4">
                    <div
                      className="w-8 h-8 rounded flex items-center justify-center font-mono text-xs font-bold"
                      style={{ backgroundColor: tierColors[i], color: '#000' }}
                    >
                      {i + 1}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="font-mono text-xs text-[var(--accent-primary)]">{tier.tier_name}</div>
                      <div className="font-mono text-[10px] text-[var(--text-muted)] break-all mt-1">
                        0x{tier.key_data}
                      </div>
                    </div>
                    <div className="flex gap-2 text-[9px] font-mono">
                      {tier.can_sign && <span className="text-red-400">SIGN</span>}
                      {tier.can_view_inputs && <span className="text-blue-400">INPUTS</span>}
                      {tier.can_view_outputs && <span className="text-yellow-400">OUTPUTS</span>}
                      {tier.can_view_balance && <span className="text-green-400">BALANCE</span>}
                    </div>
                  </div>
                ))}
                {!deriveResult.ok && (
                  <div className="panel p-3 border border-red-500">
                    <div className="text-red-500 font-mono text-xs">ERROR: {deriveResult.error}</div>
                  </div>
                )}
              </div>
            )}
          </>
        )}

        {/* Shamir Tab */}
        {activeTab === 'shamir' && (
          <>
            <div className="panel p-4">
              <div className="flex items-center gap-3 mb-3">
                <h3 className="font-mono text-xs text-[var(--accent-primary)]">GF(2^8) SHAMIR SECRET SHARING</h3>
                <button onClick={recoverShamir} className="btn-primary text-xs px-3 py-1 flex items-center gap-1">
                  <RefreshCw className="w-3 h-3" /> RECOVER
                </button>
              </div>
              <p className="text-[10px] text-[var(--text-muted)]">
                Select 2-3 shards to recover the original 32-byte secret via Lagrange interpolation in GF(2^8)
              </p>
            </div>

            <div className="panel p-4">
              <h3 className="font-mono text-xs text-[var(--accent-primary)] mb-3">SELECT SHARDS ({selectedShards.size}/2)</h3>
              <div className="space-y-2">
                {[
                  { idx: 0, name: 'OWNER Shard (x=1)' },
                  { idx: 1, name: "KUM'S NODE Shard (x=2)" },
                  { idx: 2, name: 'VAULT BACKUP Shard (x=3)' },
                ].map(({ idx, name }) => (
                  <button
                    key={idx}
                    onClick={() => toggleShard(idx)}
                    className={`w-full p-3 border rounded flex items-center gap-3 ${
                      selectedShards.has(idx)
                        ? 'border-[var(--accent-primary)] bg-[var(--accent-primary)]/10'
                        : 'border-[var(--border-subtle)] bg-[var(--bg-primary)]'
                    }`}
                  >
                    <div className={`w-5 h-5 rounded border flex items-center justify-center ${
                      selectedShards.has(idx) ? 'border-[var(--accent-primary)] bg-[var(--accent-primary)]' : 'border-[var(--text-muted)]'
                    }`}>
                      {selectedShards.has(idx) && <Check className="w-3 h-3 text-black" />}
                    </div>
                    <span className="font-mono text-xs text-[var(--text-primary)] flex-1 text-left">{name}</span>
                    {shamirResult?.shards && (
                      <span className="font-mono text-[9px] text-[var(--text-muted)] truncate max-w-48">
                        0x{shamirResult.shards[idx]?.y.slice(0, 16)}...
                      </span>
                    )}
                  </button>
                ))}
              </div>
            </div>

            {shamirResult && shamirResult.ok && (
              <div className="panel p-4 border border-[var(--accent-primary)]">
                <div className="flex items-center gap-2 mb-3">
                  {shamirResult.recovery_successful ? (
                    <><Check className="w-4 h-4 text-green-500" /><span className="font-mono text-xs text-green-500">SECRET RECOVERED SUCCESSFULLY</span></>
                  ) : (
                    <><X className="w-4 h-4 text-red-500" /><span className="font-mono text-xs text-red-500">RECOVERY FAILED</span></>
                  )}
                </div>
                {shamirResult.recovered && (
                  <div>
                    <label className="font-mono text-[10px] text-[var(--text-muted)]">Recovered Secret (32 bytes)</label>
                    <div className="font-mono text-[10px] text-[var(--text-primary)] break-all mt-1">
                      0x{shamirResult.recovered}
                    </div>
                  </div>
                )}
                {shamirResult.shards && (
                  <div className="mt-3 space-y-1">
                    {shamirResult.shards.map((shard, i) => (
                      <div key={i} className="font-mono text-[10px]">
                        <span className="text-[var(--accent-primary)]">Shard {shard.x}:</span>
                        <span className="text-[var(--text-muted)]"> 0x{shard.y.slice(0, 16)}...</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </>
        )}

        {/* Proof of Life Tab */}
        {activeTab === 'pol' && (
          <>
            <div className="panel p-4">
              <div className="flex items-center gap-3 mb-3">
                <h3 className="font-mono text-xs text-[var(--accent-primary)]">PROOF OF LIFE — TIME-WINDOW VERIFICATION</h3>
                <button onClick={generatePoL} className="btn-primary text-xs px-3 py-1 flex items-center gap-1">
                  <RefreshCw className="w-3 h-3" /> GENERATE & VERIFY
                </button>
              </div>
              <p className="text-[10px] text-[var(--text-muted)]">
                Generates a cryptographic proof using TimeLockMaintenanceKey with 10-year time window (315,360,000 seconds)
              </p>
            </div>

            {polResult && polResult.ok && polResult.proof && (
              <div className="space-y-3">
                <div className="panel p-4">
                  <h3 className="font-mono text-xs text-[var(--accent-primary)] mb-3">PROOF DATA</h3>
                  <div className="space-y-2">
                    <div>
                      <label className="font-mono text-[10px] text-[var(--text-muted)]">Timestamp</label>
                      <div className="font-mono text-[11px] text-[var(--text-primary)]">
                        {new Date(polResult.proof.timestamp * 1000).toISOString()}
                      </div>
                    </div>
                    <div>
                      <label className="font-mono text-[10px] text-[var(--text-muted)]">Commitment (fractal chaos hash)</label>
                      <div className="font-mono text-[10px] text-[var(--text-primary)] break-all mt-1">
                        0x{polResult.proof.commitment}
                      </div>
                    </div>
                    <div>
                      <label className="font-mono text-[10px] text-[var(--text-muted)]">Proof Hash (32-round fractal)</label>
                      <div className="font-mono text-[10px] text-[var(--text-primary)] break-all mt-1">
                        0x{polResult.proof.proof_hash}
                      </div>
                    </div>
                  </div>
                </div>

                <div className={`panel p-4 ${polResult.verification?.valid ? 'border-green-500' : 'border-red-500'}`}>
                  <div className="flex items-center gap-2 mb-2">
                    {polResult.verification?.valid ? (
                      <><Check className="w-4 h-4 text-green-500" /><span className="font-mono text-xs text-green-500">PROOF VALID</span></>
                    ) : (
                      <><X className="w-4 h-4 text-red-500" /><span className="font-mono text-xs text-red-500">PROOF INVALID</span></>
                    )}
                  </div>
                  <div className="font-mono text-[10px] text-[var(--text-muted)]">
                    Within 10-year time window: {polResult.verification?.within_time_window ? 'YES' : 'NO'}
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
