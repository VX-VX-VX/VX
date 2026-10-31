import { useState, useEffect, useCallback } from 'react'
import { Activity, Zap, Cpu, TrendingUp, Dices } from 'lucide-react'

// ── Wire types mirroring /api/neural/simulate and /api/crypto/canonical ─────

interface NeuralSimResult {
  ok: boolean
  virtual_tensor?: {
    total_iterations: number
    physical_weight_final: number
    final_hamiltonian_loss: number
    virtual_weights_sample_count: number
  }
  tensor_v6?: {
    landauer_heat_joules: number
    landauer_heat_ev: number
    entropy_destroyed_bits: number
    jones_invariant: number
    branching_complexity: number
    sac_flipped_bits: number
    final_vector_hex: string[] // 16 × u64 = the full 1024-bit tensor state
  }
  error?: string
}

interface CanonicalProfile {
  name: string
  address_nfa: string
  address_legacy: string
  private_key_hex: string
  coords: string[]
  hardware_uuid: string
}

interface CanonicalResponse {
  ok: boolean
  profiles?: CanonicalProfile[]
  historical_vectors?: string[]
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const sciFmt = (v: number | undefined): string => {
  if (v === undefined || !Number.isFinite(v)) return '—'
  const exp = Math.floor(Math.log10(Math.abs(v) || 1))
  if (exp >= -4 && exp < 6) return v.toExponential(4)
  return v.toExponential(4)
}

const hex64 = (h: string): bigint => {
  try {
    return BigInt(h.startsWith('0x') ? h : '0x' + h)
  } catch {
    return 0n
  }
}

export default function TensorV6Lab() {
  const [sim, setSim] = useState<NeuralSimResult | null>(null)
  const [profiles, setProfiles] = useState<CanonicalProfile[]>([])
  const [histVectors, setHistVectors] = useState<string[]>([])
  const [busy, setBusy] = useState(false)

  const run = useCallback(async (iteration: number) => {
    setBusy(true)
    try {
      const res = await fetch('/api/neural/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ iteration, steps: 1024 }),
      })
      setSim(await res.json())
    } catch (e) {
      console.error('Tensor simulation failed:', e)
    } finally {
      setBusy(false)
    }
  }, [])

  useEffect(() => {
    run(1)
    fetch('/api/crypto/canonical')
      .then(r => r.json())
      .then((d: CanonicalResponse) => {
        setProfiles(Array.isArray(d.profiles) ? d.profiles : [])
        setHistVectors(Array.isArray(d.historical_vectors) ? d.historical_vectors : [])
      })
      .catch(e => console.error('Failed to fetch canonical:', e))
  }, [run])

  const evolveOneStep = useCallback(() => {
    const next = (sim?.virtual_tensor?.total_iterations ?? 0) + 1
    run(next)
  }, [sim, run])

  const tv = sim?.tensor_v6
  const vt = sim?.virtual_tensor
  const bits = (tv?.final_vector_hex ?? []).map(hex64) // words of 64 bits
  const totalBits = bits.length * 64
  const sacPct = tv && totalBits > 0 ? (tv.sac_flipped_bits / totalBits) * 100 : null

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <header className="p-4 border-b border-[var(--border-subtle)] panel-specular">
        <div className="flex items-center gap-3">
          <Cpu className="w-5 h-5 text-[var(--accent-primary)]" />
          <div>
            <h1 className="font-mono text-sm text-[var(--accent-primary)]">TENSOR V6 LAB</h1>
            <p className="text-[10px] text-[var(--text-muted)] mt-1">
              1024-bit Hyper-Matrix • SAC Avalanche • Landauer Heat Metrics • Jones Invariant • Virtual Tensor Evolution
            </p>
          </div>
        </div>
      </header>

      <div className="flex-1 overflow-auto p-4 space-y-4">
        {/* Action Buttons */}
        <div className="flex gap-2">
          <button onClick={() => run(1)} disabled={busy} className="btn-primary text-xs px-4 py-2 flex items-center gap-2">
            <Activity className="w-3 h-3" /> {busy ? 'RUNNING…' : 'SIMULATE TENSOR V6'}
          </button>
          <button onClick={evolveOneStep} disabled={busy} className="btn-secondary text-xs px-4 py-2 flex items-center gap-2">
            <TrendingUp className="w-3 h-3" /> EVOLVE ONE STEP
          </button>
        </div>

        {/* 1024-bit Hyper-Matrix: 16 u64 words × 64 bits, straight from final_vector */}
        {bits.length > 0 && (
          <div className="panel p-4">
            <h3 className="font-mono text-xs text-[var(--accent-primary)] mb-3">
              HYPER-MATRIX ({totalBits}-BIT · {bits.length} WORDS × 64 BITS)
            </h3>
            <div className="space-y-[3px]">
              {bits.map((word, wi) => (
                <div key={wi} className="flex items-center gap-2">
                  <span className="font-mono text-[8px] text-[var(--text-muted)] w-10">W{wi.toString().padStart(2, '0')}</span>
                  <div className="flex gap-[1px] flex-1">
                    {Array.from({ length: 64 }, (_, bi) => {
                      const bit = Number((word >> BigInt(63 - bi)) & 1n)
                      return (
                        <div
                          key={bi}
                          title={`word ${wi} · bit ${63 - bi} · ${bit}`}
                          className="flex-1 h-3 rounded-[1px]"
                          style={{
                            backgroundColor: bit ? 'var(--accent-primary)' : 'var(--border-subtle)',
                            opacity: bit ? 0.55 + ((Number(word >> BigInt(63 - bi)) & 7) / 8) * 0.45 : 1,
                          }}
                        />
                      )
                    })}
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-2 flex flex-wrap gap-3 font-mono text-[9px] text-[var(--text-muted)]">
              {bits.map((w, i) => (
                <span key={i}>W{i}: 0x{w.toString(16).padStart(16, '0')}</span>
              ))}
            </div>
          </div>
        )}

        {/* SAC + Branching */}
        {tv && (
          <div className="panel p-4">
            <h3 className="font-mono text-xs text-[var(--accent-primary)] mb-3">SAC AVALANCHE & STRUCTURE</h3>
            <div className="grid grid-cols-3 gap-4">
              <div className="bg-[var(--bg-primary)] rounded p-3 border border-[var(--border-subtle)]">
                <div className="font-mono text-[10px] text-[var(--text-muted)]">SAC Flipped Bits</div>
                <div className="font-mono text-xl text-[var(--accent-primary)] mt-1">{tv.sac_flipped_bits}/{totalBits}</div>
                <div className="text-[9px] text-[var(--text-muted)] mt-1">{sacPct?.toFixed(1)}% · target ~50%</div>
                <div className="mt-2 h-2 bg-[var(--bg-primary)] rounded-full overflow-hidden">
                  <div
                    className={`h-full ${sacPct !== null && sacPct >= 40 && sacPct <= 60 ? 'bg-emerald-400' : 'bg-amber-400'}`}
                    style={{ width: `${Math.min(100, sacPct ?? 0)}%` }}
                  />
                </div>
              </div>
              <div className="bg-[var(--bg-primary)] rounded p-3 border border-[var(--border-subtle)]">
                <div className="font-mono text-[10px] text-[var(--text-muted)]">Branching Complexity</div>
                <div className="font-mono text-xl text-[var(--accent-primary)] mt-1">{tv.branching_complexity}</div>
                <div className="text-[9px] text-[var(--text-muted)] mt-1">Tensor branching paths</div>
              </div>
              <div className="bg-[var(--bg-primary)] rounded p-3 border border-[var(--border-subtle)]">
                <div className="font-mono text-[10px] text-[var(--text-muted)]">Entropy Destroyed</div>
                <div className="font-mono text-xl text-[var(--accent-primary)] mt-1">
                  {tv.entropy_destroyed_bits.toLocaleString()} bits
                </div>
                <div className="text-[9px] text-[var(--text-muted)] mt-1">Irreversible computation</div>
              </div>
            </div>
          </div>
        )}

        {/* Landauer Heat Metrics */}
        {tv && (
          <div className="panel p-4">
            <h3 className="font-mono text-xs text-[var(--accent-primary)] mb-3">LANDAUER HEAT METRICS</h3>
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-[var(--bg-primary)] rounded p-3 border border-[var(--border-subtle)]">
                <div className="flex items-center gap-2 mb-2">
                  <Zap className="w-4 h-4 text-yellow-500" />
                  <span className="font-mono text-[10px] text-[var(--text-muted)]">Total Heat</span>
                </div>
                <div className="font-mono text-xl text-yellow-500">{sciFmt(tv.landauer_heat_joules)} J</div>
              </div>
              <div className="bg-[var(--bg-primary)] rounded p-3 border border-[var(--border-subtle)]">
                <div className="flex items-center gap-2 mb-2">
                  <Activity className="w-4 h-4 text-red-500" />
                  <span className="font-mono text-[10px] text-[var(--text-muted)]">Heat per Op</span>
                </div>
                <div className="font-mono text-xl text-red-500">{sciFmt(tv.landauer_heat_ev)} eV</div>
                <div className="text-[9px] text-[var(--text-muted)] mt-1">Landauer limit: 0.017 eV at 300K</div>
              </div>
            </div>
          </div>
        )}

        {/* Jones Invariant */}
        {tv && (
          <div className="panel p-4">
            <h3 className="font-mono text-xs text-[var(--accent-primary)] mb-2">JONES INVARIANT</h3>
            <div className="font-mono text-[11px] text-[var(--text-primary)] break-all">
              {tv.jones_invariant.toLocaleString()}
            </div>
          </div>
        )}

        {/* Virtual Tensor Evolution */}
        <div className="panel p-4">
          <div className="flex items-center gap-3 mb-3">
            <h3 className="font-mono text-xs text-[var(--accent-primary)]">VIRTUAL TENSOR EVOLUTION</h3>
            <span className="font-mono text-[10px] text-[var(--text-muted)]">
              iteration: {vt?.total_iterations ?? '—'}
            </span>
          </div>
          {vt ? (
            <div className="grid grid-cols-3 gap-3">
              <div className="bg-[var(--bg-primary)] rounded p-2 border border-[var(--border-subtle)]">
                <div className="font-mono text-[9px] text-[var(--text-muted)]">PHYSICAL WEIGHT FINAL</div>
                <div className="font-mono text-[11px] text-[var(--accent-primary)] mt-1 break-all">
                  {vt.physical_weight_final.toExponential(6)}
                </div>
              </div>
              <div className="bg-[var(--bg-primary)] rounded p-2 border border-[var(--border-subtle)]">
                <div className="font-mono text-[9px] text-[var(--text-muted)]">HAMILTONIAN LOSS</div>
                <div className="font-mono text-[11px] text-[var(--accent-primary)] mt-1">
                  {vt.final_hamiltonian_loss.toFixed(6)}
                </div>
              </div>
              <div className="bg-[var(--bg-primary)] rounded p-2 border border-[var(--border-subtle)]">
                <div className="font-mono text-[9px] text-[var(--text-muted)]">WEIGHT SAMPLES</div>
                <div className="font-mono text-[11px] text-[var(--accent-primary)] mt-1">
                  {vt.virtual_weights_sample_count.toLocaleString()}
                </div>
              </div>
            </div>
          ) : (
            <div className="text-[10px] text-[var(--text-muted)] font-mono">Press "SIMULATE TENSOR V6" to initialize</div>
          )}
        </div>

        {/* Canonical Identity Profiles */}
        {profiles.length > 0 && (
          <div className="panel p-4">
            <h3 className="font-mono text-xs text-[var(--accent-primary)] mb-3 flex items-center gap-2">
              <Dices className="w-3.5 h-3.5" /> CANONICAL IDENTITY PROFILES
            </h3>
            <div className="space-y-2">
              {profiles.map((profile, i) => (
                <div key={profile.name ?? i} className="bg-[var(--bg-primary)] rounded p-3 border border-[var(--border-subtle)]">
                  <div className="font-mono text-xs text-[var(--accent-primary)] mb-2">{profile.name ?? `profile ${i}`}</div>
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <span className="font-mono text-[9px] text-[var(--text-muted)]">NFA:</span>
                      <div className="font-mono text-[9px] text-[var(--text-primary)] break-all mt-0.5">{profile.address_nfa}</div>
                    </div>
                    <div>
                      <span className="font-mono text-[9px] text-[var(--text-muted)]">Legacy OFA:</span>
                      <div className="font-mono text-[9px] text-[var(--text-primary)] break-all mt-0.5">{profile.address_legacy}</div>
                    </div>
                    <div>
                      <span className="font-mono text-[9px] text-[var(--text-muted)]">Private Key:</span>
                      <div className="font-mono text-[9px] text-[var(--text-primary)] break-all mt-0.5">{profile.private_key_hex}</div>
                    </div>
                    <div>
                      <span className="font-mono text-[9px] text-[var(--text-muted)]">Coords:</span>
                      <div className="font-mono text-[9px] text-[var(--text-primary)] break-all mt-0.5">
                        {(profile.coords ?? []).join(' · ')}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Historical Entropy Vectors */}
        {histVectors.length > 0 && (
          <div className="panel p-4">
            <h3 className="font-mono text-xs text-[var(--accent-primary)] mb-3">HISTORICAL ENTROPY VECTORS</h3>
            <div className="flex gap-1 flex-wrap">
              {histVectors.map((vec, vi) => (
                <span
                  key={vi}
                  title={vec}
                  className="font-mono text-[8px] bg-[var(--bg-tertiary)] px-1 py-0.5 rounded text-[var(--text-muted)]"
                >
                  {vec.slice(0, 14)}…
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
