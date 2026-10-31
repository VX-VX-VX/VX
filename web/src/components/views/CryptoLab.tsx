import { useState } from 'react'
import { useWorkspace } from '../../contexts/WorkspaceContext'
import { Play, RefreshCw, Copy, EyeOff } from 'lucide-react'

const PRESET_SEEDS = [
  { label: 'Canonical Genesis', value: 'd15c93e51137cb32d0f0ab68524e91451f0d8a7e584a52ccad833d7c9c35396c' },
  { label: 'Seed #2', value: 'e76a1d401b5c3b803d9e909a1c7d7b5893f89e991160bfea87d56b9292a9eca5' },
  { label: 'Seed #3', value: 'aa0e37b14c1157a6cfeea4036e82f03958b6be4754e88d7c4817c98933cbb5eb' },
]

const ROUND_PRESETS = [10, 100, 500, 1000]

export default function CryptoLab() {
  const { cryptoLab, executeCryptoLab } = useWorkspace()
  const [seed, setSeed] = useState(PRESET_SEEDS[0].value)
  const [rounds, setRounds] = useState(1000)
  const [showGhostText, setShowGhostText] = useState(false)

  const handleRun = async () => {
    await executeCryptoLab(seed, rounds, false)
  }

  const handleSac = async () => {
    await executeCryptoLab(seed, rounds, true)
  }

  if (!cryptoLab) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="panel p-8 text-center max-w-md">
          <h2 className="font-mono text-sm text-[var(--accent-primary)] mb-4">17-D WIF & GALOIS ATTRACTOR LAB</h2>
          <p className="text-[var(--text-muted)] mb-4 text-xs">
            Run the 3-Trunk Galois Attractor with Secure CRT moduli and compute all 17-D WIF formats
            from the C++ core.
          </p>
          <button
            onClick={handleRun}
            className="btn-primary mx-auto flex items-center gap-2"
          >
            <Play className="w-4 h-4" /> RUN GOLAS ACTOR
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <header className="p-4 border-b border-[var(--border-subtle)] panel-specular">
        <h1 className="font-mono text-xs text-[var(--accent-primary)]">VORTEX SOVEREIGN OS — CRYPTO LAB</h1>
        <p className="text-[11px] text-[var(--text-muted)] mt-1">
          P = 2^1024-2^64-1747 • Q = 2^1024-2^888-3943 • R = 2^1024-2^512-267799
        </p>
      </header>

      <div className="flex-1 overflow-auto p-4 space-y-4">
        {/* Controls */}
        <div className="panel p-4">
          <div className="grid grid-cols-4 gap-4 items-end">
            <div>
              <label className="font-mono text-[10px] text-[var(--text-muted)] block mb-1">SEED (HEX)</label>
              <select
                value={seed}
                onChange={e => setSeed(e.target.value)}
                className="input-field w-full text-[10px]"
              >
                {PRESET_SEEDS.map(s => (
                  <option key={s.label} value={s.value}>{s.label}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="font-mono text-[10px] text-[var(--text-muted)] block mb-1">ROUNDS</label>
              <div className="flex gap-1">
                {ROUND_PRESETS.map(r => (
                  <button
                    key={r}
                    onClick={() => setRounds(r)}
                    className={`px-3 py-1 text-[10px] font-mono rounded transition-all ${
                      rounds === r
                        ? 'bg-[var(--accent-primary)] text-[var(--bg-primary)]'
                        : 'bg-[var(--bg-elevated)] text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                    }`}
                  >
                    {r}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="font-mono text-[10px] text-[var(--text-muted)] block mb-1">MODULI</label>
              <select className="input-field w-full text-[10px]">
                <option>Secure CRT (Prime-Proven)</option>
                <option>Classic (Legacy)</option>
              </select>
            </div>

            <div className="flex gap-2">
              <button onClick={handleRun} className="btn-primary py-2 px-4 text-[10px]">
                <Play className="w-3 h-3 mr-1" /> RUN
              </button>
              <button onClick={handleSac} className="btn-secondary py-2 px-4 text-[10px]">
                <RefreshCw className="w-3 h-3 mr-1" /> SAC PROBE
              </button>
            </div>
          </div>
        </div>

        {/* Results: Coordinates */}
        <div className="panel p-4">
          <h3 className="font-mono text-[10px] text-[var(--accent-primary)] mb-3">3-TRUNK ATTRACTOR COORDINATES</h3>
          <div className="grid grid-cols-3 gap-4">
            <CoordinateCard
              label="TRUNK P (X)"
              hex={cryptoLab.coordinates.x_hex}
              color="accent-primary"
            />
            <CoordinateCard
              label="TRUNK Q (Y)"
              hex={cryptoLab.coordinates.y_hex}
              color="accent-secondary"
            />
            <CoordinateCard
              label="TRUNK R (Z)"
              hex={cryptoLab.coordinates.z_hex}
              color="amber"
            />
          </div>
        </div>

        {/* Addresses & WIF */}
        <div className="panel p-4">
          <h3 className="font-mono text-[10px] text-[var(--accent-primary)] mb-3">ADDRESS & WIF FORMATS</h3>
          <div className="space-y-3">
            <div>
              <label className="font-mono text-[9px] text-[var(--text-muted)]">NFA_v6 Address</label>
              <CopyableValue value={cryptoLab.address_nfa} />
            </div>
            <div>
              <label className="font-mono text-[9px] text-[var(--text-muted)]">OFA_v2 Address</label>
              <CopyableValue value={cryptoLab.address_ofa} />
            </div>

            <div className="grid grid-cols-2 gap-4 pt-3 border-t border-[var(--border-subtle)]">
              <div>
                <label className="font-mono text-[9px] text-[var(--accent-primary)]">RECORD WIF (Runes)</label>
                <div className="text-2xl my-2 text-center" style={{ fontFamily: 'sans-serif' }}>
                  {cryptoLab.wif.record.split('').map((rune, i) => (
                    <span
                      key={i}
                      className="inline-block animate-pulse"
                      style={{ animationDelay: `${i * 100}ms` }}
                    >
                      {rune}
                    </span>
                  ))}
                </div>
                <CopyableValue value={cryptoLab.wif.record} />
              </div>
              <div className="space-y-2">
                <div>
                  <label className="font-mono text-[9px] text-[var(--accent-secondary)]">COMPACT WIF</label>
                  <CopyableValue value={cryptoLab.wif.compact} mono />
                </div>
                <div>
                  <label className="font-mono text-[9px] text-[var(--text-muted)]">COMPRESSED WIF</label>
                  <CopyableValue value={cryptoLab.wif.compressed} mono />
                </div>
                <div>
                  <label className="font-mono text-[9px] text-[var(--accent-primary)]">GHOST WIF (Steganography)</label>
                  <div className="relative">
                    <textarea
                      value={cryptoLab.wif.ghost}
                      readOnly
                      onClick={() => setShowGhostText(!showGhostText)}
                      className={`input-field w-full h-20 text-[10px] resize-none ${!showGhostText ? 'blur-sm' : ''}`}
                    />
                    {!showGhostText && (
                      <EyeOff className="absolute top-1 right-1 w-4 h-4 text-[var(--text-muted)] cursor-pointer" onClick={() => setShowGhostText(true)} />
                    )}
                  </div>
                  <div className="flex gap-2 mt-1 text-[9px] text-[var(--text-muted)]">
                    <span>ZWSP: U+200B (zero-width space)</span>
                    <span>ZWNJ: U+200C (zero-width non-joiner)</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* SAC Probe Results */}
        {cryptoLab.sac && cryptoLab.sac.length > 0 && (
          <div className="panel p-4">
            <h3 className="font-mono text-[10px] text-[var(--accent-primary)] mb-3">SAC AVALANCHE PROBE</h3>
            <div className="space-y-2">
              {cryptoLab.sac.slice(0, 10).map(s => (
                <div key={s.round} className="flex items-center gap-2 font-mono text-[10px]">
                  <span className="w-8 text-right text-[var(--text-muted)]">R{s.round}</span>
                  <div className="flex-1 h-4 bg-[var(--bg-primary)] rounded-full overflow-hidden">
                    <div
                      className="h-full bg-[var(--accent-primary)] rounded-full"
                      style={{ width: `${s.percentage}%` }}
                    />
                  </div>
                  <span className="w-12 text-right tabular-nums text-[var(--text-primary)]">{s.percentage.toFixed(2)}%</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Timing */}
        <div className="panel p-4">
          <div className="flex items-center justify-between font-mono text-[10px]">
            <span className="text-[var(--text-muted)]">Execution Time</span>
            <span className="text-[var(--accent-primary)] tabular-nums">{cryptoLab.execution_time_ms.toFixed(3)} ms</span>
          </div>
          <div className="flex items-center justify-between font-mono text-[10px] mt-1">
            <span className="text-[var(--text-muted)]">Throughput (1000 rounds)</span>
            <span className="text-[var(--accent-secondary)] tabular-nums">
              {(1000 / (cryptoLab.execution_time_ms * rounds / 1000)).toFixed(0)} rounds/sec
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}

function CoordinateCard({ label, hex, color }: { label: string; hex: string; color: string }) {
  return (
    <div className="bg-[var(--bg-primary)] rounded p-3 border border-[var(--border-subtle)]">
      <div className={`font-mono text-[10px] text-[var(--${color})]`}>{label}</div>
      <div className="font-mono text-[9px] text-[var(--text-primary)] mt-2 tabular-nums break-all">
        0x{hex.slice(0, 32)}...{hex.slice(-32)}
      </div>
      <div className="text-[var(--text-muted)] font-mono text-[9px] mt-1">
        {hex.length} bits
      </div>
    </div>
  )
}

function CopyableValue({ value, mono = false }: { value: string; mono?: boolean }) {
  const copy = () => navigator.clipboard.writeText(value)
  return (
    <div className="flex items-center gap-1">
      <input
        type="text"
        value={value}
        readOnly
        className={`flex-1 ${mono ? 'font-mono text-[10px]' : 'text-xs'} bg-[var(--bg-elevated)] border border-[var(--border-subtle)] rounded px-2 py-1 truncate`}
      />
      <button onClick={copy} className="btn-ghost p-1" title="Copy">
        <Copy className="w-3 h-3" />
      </button>
    </div>
  )
}