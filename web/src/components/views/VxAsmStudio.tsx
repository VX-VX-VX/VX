import { useState, useMemo, useCallback } from 'react'
import { Code2, Play, ChevronRight, ChevronLeft, RotateCcw, Zap, Thermometer, Cpu } from 'lucide-react'

// ── Wire types mirroring /api/vm/execute_trace and /api/vm/htlc_swap ────────

interface TraceStep {
  step_index: number
  pc: number
  opcode: number
  mnemonic: string
  erased_bits: number
  hamming_flips: number
  step_landauer_gas: number
  cumulative_landauer_gas: number
  registers: number[] // R0..R7 snapshots after this step
  stack_top: number
}

interface ExecuteTraceResult {
  ok: boolean
  error?: string | null
  bytecode_hex?: string
  disassembly?: string
  trace?: TraceStep[]
  final_registers?: number[]
  total_landauer_gas?: number
  total_erased_bits?: number
  total_hamming_flips?: number
  cycles_used?: number
  vm_state_root?: string
}

interface HtlcSwapResult {
  ok: boolean
  mode?: string
  outcome?: string
  vm_branch_marker?: number
  hash_lock?: string
  error?: string
}

// ── Quick-load contract templates ────────────────────────────────────────────

const TEMPLATES: Record<string, { label: string; source: string }> = {
  htlc: {
    label: 'HTLC Atomic Swap',
    source: `; HTLC atomic swap — claim branch requires a matching
; preimage (R0/R1 carry the canonical 16-byte preimage),
; R4 carries the timelock height.
LOAD_IMM R2 0x4afd50cbc9962dee
LOAD_IMM R3 0xaba25f54a3d76d5d
LOAD_IMM R4 100
HTLC_VERIFY
JNZ refund_branch
LOAD_IMM R6 1
HALT
refund_branch:
LOAD_IMM R6 2
HALT
`,
  },
  galois: {
    label: 'Galois F₂⁸ Mul & Sponge',
    source: `; GF(2^8) polynomial multiplication + sponge hash mixing
LOAD_IMM R0 0x57
LOAD_IMM R1 0x83
GALOIS_MUL R2 R0 R1
LOAD_IMM R3 0xA5
SOLINAS_RED R4 R3
SPONGE_HASH R5 R2
HALT
`,
  },
  landauer: {
    label: 'Landauer Entropy Stress',
    source: `; Thermodynamic stress: maximize 1->0 bit erasures per step
LOAD_IMM R0 0xFFFFFFFFFFFFFFFF
LOAD_IMM R1 0xFFFFFFFFFFFFFFFF
XOR R2 R0 R1
AND R3 R0 R1
ROTL R4 R0
MUL R5 R0 R1
HALT
`,
  },
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const hex64 = (v: number): string => {
  const big = BigInt.asUintN(64, BigInt(Math.floor(v)))
  return '0x' + big.toString(16).padStart(16, '0')
}

const dec64 = (v: number): string => BigInt.asUintN(64, BigInt(Math.floor(v))).toString(10)

// Bits that flipped between two register snapshots.
const changedBits = (a: number, b: number): number =>
  Number((BigInt.asUintN(64, BigInt(Math.floor(a))) ^ BigInt.asUintN(64, BigInt(Math.floor(b)))))

function popcount(bigVal: number): number {
  let n = 0
  let v = BigInt.asUintN(64, BigInt(Math.floor(bigVal)))
  while (v !== 0n) {
    if (v & 1n) ++n
    v >>= 1n
  }
  return n
}

export default function VxAsmStudio() {
  const [source, setSource] = useState(TEMPLATES.htlc.source)
  const [result, setResult] = useState<ExecuteTraceResult | null>(null)
  const [pc, setPc] = useState(0) // current trace cursor
  const [htlc, setHtlc] = useState<HtlcSwapResult | null>(null)
  const [busy, setBusy] = useState(false)

  const trace = result?.trace ?? []
  const step: TraceStep | null = trace[pc] ?? null
  const prevStep: TraceStep | null = pc > 0 ? trace[pc - 1] : null
  const maxGas = useMemo(
    () => trace.reduce((m, t) => Math.max(m, t.cumulative_landauer_gas), 1),
    [trace],
  )

  const runTrace = useCallback(async () => {
    setBusy(true)
    setHtlc(null)
    try {
      const res = await fetch('/api/vm/execute_trace', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ asm: source, max_steps: 1000 }),
      })
      const data: ExecuteTraceResult = await res.json()
      setResult(data)
      setPc(0)
    } catch (e) {
      console.error('execute_trace failed:', e)
    } finally {
      setBusy(false)
    }
  }, [source])

  const runHtlcSwap = useCallback(async () => {
    setBusy(true)
    try {
      const res = await fetch('/api/vm/htlc_swap', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'claim', preimage: 777, height: 99 }),
      })
      const data: HtlcSwapResult = await res.json()
      setHtlc(data)
    } catch (e) {
      console.error('htlc_swap failed:', e)
    } finally {
      setBusy(false)
    }
  }, [])

  const gasPct = step ? Math.min(100, (step.cumulative_landauer_gas / maxGas) * 100) : 0

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <header className="p-4 border-b border-[var(--border-subtle)] panel-specular">
        <div className="flex items-center gap-3">
          <Code2 className="w-5 h-5 text-[var(--accent-primary)]" />
          <div>
            <h1 className="font-mono text-sm text-[var(--accent-primary)]">VX-ASM STUDIO</h1>
            <p className="text-[10px] text-[var(--text-muted)] mt-1">
              Smart-Contract IDE • 24 Opcodes • Two-Pass Assembler • Landauer Thermodynamic Gas Meter
            </p>
          </div>
        </div>
      </header>

      <div className="flex-1 overflow-auto p-4 grid grid-cols-1 xl:grid-cols-2 gap-4">
        {/* ── Left column: editor + controls ── */}
        <div className="space-y-4">
          <div className="panel p-3">
            <div className="flex flex-wrap gap-2 mb-2">
              {Object.entries(TEMPLATES).map(([key, t]) => (
                <button
                  key={key}
                  onClick={() => setSource(t.source)}
                  className="btn-secondary text-[10px] px-2 py-1"
                >
                  {t.label}
                </button>
              ))}
            </div>
            <textarea
              value={source}
              onChange={e => setSource(e.target.value)}
              spellCheck={false}
              rows={14}
              className="w-full bg-transparent border border-[var(--border-subtle)] rounded p-2 font-mono text-[11px] text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-primary)]"
            />
            <div className="flex flex-wrap gap-2 mt-2">
              <button onClick={runTrace} disabled={busy} className="btn-primary text-xs px-3 py-1.5 flex items-center gap-1.5">
                <Play className="w-3 h-3" /> COMPILE & RUN TRACE
              </button>
              <button onClick={() => setPc(p => Math.max(0, p - 1))} disabled={!trace.length || pc === 0} className="btn-secondary text-xs px-3 py-1.5 flex items-center gap-1.5">
                <ChevronLeft className="w-3 h-3" /> STEP BACK
              </button>
              <button onClick={() => setPc(p => Math.min(trace.length - 1, p + 1))} disabled={!trace.length || pc >= trace.length - 1} className="btn-secondary text-xs px-3 py-1.5 flex items-center gap-1.5">
                <ChevronRight className="w-3 h-3" /> STEP FWD
              </button>
              <button onClick={() => { setPc(0); setResult(null); setHtlc(null) }} className="btn-secondary text-xs px-3 py-1.5 flex items-center gap-1.5">
                <RotateCcw className="w-3 h-3" /> RESET
              </button>
              <button onClick={runHtlcSwap} disabled={busy} className="btn-secondary text-xs px-3 py-1.5 flex items-center gap-1.5">
                <Zap className="w-3 h-3" /> EXECUTE HTLC SWAP
              </button>
            </div>
          </div>

          {/* Compiled artifact */}
          {result && (
            <div className="panel p-3">
              <h3 className="font-mono text-xs text-[var(--accent-primary)] mb-2">COMPILED BYTECODE</h3>
              <div className="font-mono text-[10px] text-[var(--text-muted)] break-all">
                {result.bytecode_hex ?? '—'}
              </div>
              <div className="mt-2 flex flex-wrap gap-3 text-[10px] font-mono">
                <span>ok: <span className={result.ok ? 'text-emerald-400' : 'text-red-400'}>{String(result.ok)}</span></span>
                {result.error && <span className="text-red-400">{result.error}</span>}
                <span>cycles: {result.cycles_used ?? '—'}</span>
                <span>state_root: {result.vm_state_root?.slice(0, 16) ?? '—'}…</span>
              </div>
              {result.disassembly && (
                <pre className="mt-2 font-mono text-[10px] text-[var(--text-muted)] whitespace-pre-wrap">
                  {result.disassembly}
                </pre>
              )}
            </div>
          )}

          {/* HTLC swap outcome */}
          {htlc && (
            <div className="panel p-3">
              <h3 className="font-mono text-xs text-[var(--accent-primary)] mb-2">HTLC ATOMIC SWAP</h3>
              <div className="font-mono text-[10px] space-y-1">
                <div>outcome: <span className={htlc.outcome === 'CLAIMED' ? 'text-emerald-400' : htlc.outcome === 'REFUNDED' ? 'text-amber-400' : 'text-red-400'}>{htlc.outcome}</span></div>
                <div>branch_marker: {htlc.vm_branch_marker}</div>
                <div>hash_lock: {htlc.hash_lock?.slice(0, 24)}…</div>
              </div>
            </div>
          )}
        </div>

        {/* ── Right column: registers + thermodynamics ── */}
        <div className="space-y-4">
          <div className="panel p-3">
            <h3 className="font-mono text-xs text-[var(--accent-primary)] mb-2 flex items-center gap-2">
              <Cpu className="w-3.5 h-3.5" /> REGISTERS R0..R7
              <span className="text-[var(--text-muted)]">
                {step ? `PC ${step.pc} · ${step.mnemonic}` : 'idle'}
              </span>
            </h3>
            <table className="w-full font-mono text-[10px]">
              <thead>
                <tr className="text-[var(--text-muted)] text-left">
                  <th className="py-1">REG</th>
                  <th>HEX (u64)</th>
                  <th>DECIMAL</th>
                  <th className="text-right">Δ BITS</th>
                </tr>
              </thead>
              <tbody>
                {Array.from({ length: 8 }, (_, r) => {
                  const cur = step?.registers[r] ?? 0
                  const prev = prevStep?.registers[r] ?? 0
                  const delta = changedBits(prev, cur)
                  const dirty = delta !== 0
                  return (
                    <tr key={r} className={dirty ? 'bg-[var(--accent-primary)]/10' : ''}>
                      <td className="py-0.5 text-[var(--accent-primary)]">R{r}</td>
                      <td>{hex64(cur)}</td>
                      <td className="text-[var(--text-muted)]">{dec64(cur)}</td>
                      <td className={`text-right ${dirty ? 'text-amber-400' : 'text-[var(--text-muted)]'}`}>
                        {dirty ? `${popcount(delta)} bits flipped` : '—'}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          {/* Landauer thermometer */}
          <div className="panel p-3">
            <h3 className="font-mono text-xs text-[var(--accent-primary)] mb-2 flex items-center gap-2">
              <Thermometer className="w-3.5 h-3.5" /> LANDAUER GAS THERMOMETER
            </h3>
            <div className="h-3 rounded-full bg-[var(--border-subtle)] overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-amber-500 to-red-500 transition-all"
                style={{ width: `${gasPct}%` }}
              />
            </div>
            <div className="mt-1 font-mono text-[10px] text-[var(--text-muted)] flex justify-between">
              <span>step gas: {step?.step_landauer_gas ?? 0}</span>
              <span>total: {result?.total_landauer_gas ?? 0} µKT·ln2</span>
              <span>erased bits: {result?.total_erased_bits ?? 0}</span>
            </div>

            {/* Per-instruction heat chart */}
            <div className="mt-3 flex items-end gap-[2px] h-20">
              {trace.map((t, i) => {
                const h = Math.max(2, (t.cumulative_landauer_gas / maxGas) * 100)
                return (
                  <div
                    key={t.step_index}
                    title={`#${t.step_index} ${t.mnemonic} · erased ${t.erased_bits}b · gas ${t.step_landauer_gas}`}
                    className={`flex-1 rounded-t ${i === pc ? 'bg-amber-400' : 'bg-[var(--accent-primary)]/60'}`}
                    style={{ height: `${h}%` }}
                  />
                )
              })}
            </div>
            <div className="mt-1 font-mono text-[9px] text-[var(--text-muted)]">
              cumulative heat per instruction — amber bar = current PC
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
