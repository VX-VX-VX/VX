import React, { useState } from 'react'
import { useWorkspace } from '../../contexts/WorkspaceContext'
import { Bug, Skull, Terminal, AlertTriangle, ShieldCheck, Flame } from 'lucide-react'

const ATTACK_TYPES = [
  { id: 'tamper_amount', label: 'Flip 1 Bit in Amount Post-Sign', icon: Bug, color: 'amber', desc: 'Flips a single bit in transaction amount after cocoon_proof signing' },
  { id: 'tamper_receiver', label: 'Hijack Receiver NFA Address', icon: Bug, color: 'amber', desc: 'Modifies receiver address after signing' },
  { id: 'pq_mitm_forgery', label: 'PQ MITM Forgery (WOTS+ / XMSS Barrier)', icon: ShieldCheck, color: 'cyan', desc: 'Attacker rehashes the tx AND replays a WOTS+ witness — blocked by the Winternitz checksum' },
  { id: 'double_miner', label: 'Double MINER_ / 1001 VX Inflation Exploit', icon: Skull, color: 'red', desc: 'Attempts to insert duplicate coinbase or exceed reward limit' },
  { id: 'excess_reward', label: 'Excess Miner Reward Exploit', icon: Skull, color: 'red', desc: 'Attempts to claim more than 1000 VX reward' },
  { id: 'unauthorized_genesis', label: 'Unauthorized GENESIS Mint on Block #5', icon: Skull, color: 'red', desc: 'Attempts to mint coins with GENESIS tag outside height 0 or 1' },
  { id: 'dust_spam_tdi', label: 'Dust Spam Attack (TDI Filter)', icon: AlertTriangle, color: 'yellow', desc: 'Submits low-density transaction to trigger economic threshold' },
  { id: 'sac_avalanche_probe', label: 'VortexSponge256 SAC Avalanche Test', icon: Terminal, color: 'cyan', desc: 'Flips 1 bit in block header and measures diffusion across 256-bit hash' },
]

interface PqSignResult {
  ok: boolean
  verified: boolean
  pq_scheme: string
  shor_vulnerable_ops: number
  grover_security_bits: number
  classical_security_bits: number
  wots_chains: number
  wots_w: number
  xmss_height: number
  xmss_leaves: number
  witness_size_bytes: number
  tx_frame_bytes: number
  leaf_index: number
  subtree_index: number
  pq_pubkey_root: string
  witness_digest: string
  msg_digest: string
  cocoon_proof_hex: string
  winternitz_checksum: number
  keygen_cycles: number
  keygen_us: number
  sign_cycles: number
  sign_us: number
  verify_us: number
  vault_burn_verified: boolean
}

interface PqVerifyResult {
  ok: boolean
  verified: boolean
  wots_verify_ok: boolean
  anchor_ok: boolean
  mitm_rehash_attack_rejected: boolean
  wots_forward_chain_forgery_rejected: boolean
  merkle_path_tamper_rejected: boolean
  winternitz_checksum: number
  verify_us: number
}

export default function SecuritySandbox() {
  const { executeAudit, auditResult, executePqSign, executePqVerify } = useWorkspace()
  const [running, setRunning] = useState<string | null>(null)
  const [pqSign, setPqSign] = useState<PqSignResult | null>(null)
  const [pqVerify, setPqVerify] = useState<PqVerifyResult | null>(null)
  const [pqBusy, setPqBusy] = useState(false)

  const handleAttack = async (type: string) => {
    setRunning(type)
    try {
      await executeAudit(type)
    } catch (e) {
      console.error(e)
    } finally {
      setRunning(null)
    }
  }

  const handlePqSign = async () => {
    setPqBusy(true)
    try {
      setPqSign(await executePqSign({ nonce: Math.floor(Math.random() * 65536) }))
      setPqVerify(null)
    } catch (e) {
      console.error(e)
    } finally {
      setPqBusy(false)
    }
  }

  const handlePqVerify = async () => {
    setPqBusy(true)
    try {
      setPqVerify(await executePqVerify())
    } catch (e) {
      console.error(e)
    } finally {
      setPqBusy(false)
    }
  }

  return (
    <div className="h-full flex flex-col p-4 overflow-auto">
      <header className="mb-6">
        <h1 className="font-mono text-xs text-[var(--accent-primary)]">RED-TEAM SECURITY SANDBOX</h1>
        <p className="text-[11px] text-[var(--text-muted)] mt-1">
          Interactive cryptographic attack simulation against VortexSponge256 • cocoon_proof • TDI Filter • Minting Rules
        </p>
      </header>

      <div className="grid grid-cols-4 gap-3 mb-6">
        {ATTACK_TYPES.map(attack => (
          <button
            key={attack.id}
            onClick={() => handleAttack(attack.id)}
            disabled={!!running}
            className={`panel panel-specular p-4 text-center transition-all disabled:opacity-50 ${
              running === attack.id ? 'animate-pulse ring-2 ring-[var(--accent-primary)]' : ''
            }`}
          >
            <div className={`w-10 h-10 mx-auto rounded-full bg-[var(--accent-secondary)]/10 flex items-center justify-center mb-2`}>
              {attack.icon && React.createElement(attack.icon, { className: "w-5 h-5 text-[var(--accent-secondary)]" })}
            </div>
            <div className="font-mono text-[10px] mb-1">{attack.label.substring(0, 20)}...</div>
            <div className="text-[9px] text-[var(--text-muted)]">{attack.desc.substring(0, 60)}...</div>
          </button>
        ))}
      </div>

      {auditResult && (
        <div className="panel panel-specular p-4 flex-1 overflow-auto">
          <div className="flex items-center justify-between mb-3">
            <h2 className="font-mono text-xs text-[var(--accent-primary)]">AUDIT RESULT</h2>
            <span className={`font-mono text-[10px] px-2 py-0.5 rounded ${
              auditResult?.blocked ? 'bg-red-500/10 text-red-400' : 'bg-green-500/10 text-green-400'
            }`}>
              {auditResult?.blocked ? 'BLOCKED' : 'PASSED'}
            </span>
          </div>
          <div className="font-mono text-[10px] space-y-2">
            {auditResult?.engine_verdict && (
              <div className="p-2 bg-[var(--bg-elevated)] rounded border-l-2 border-red-500">
                <span className="text-red-400">▼ {auditResult.engine_verdict}</span>
              </div>
            )}
            {typeof auditResult?.tdi === 'number' && (
              <div>TDI Score: <span className="tabular-nums">{auditResult.tdi.toFixed(4)}</span></div>
            )}
            {typeof auditResult?.sac_flipped_bits === 'number' && (
              <div>
                SAC Flipped Bits: <span className="tabular-nums">{auditResult.sac_flipped_bits}</span>
                <div className="mt-2 h-2 bg-[var(--bg-primary)] rounded-full overflow-hidden">
                  <div
                    className="h-full bg-[var(--accent-primary)]"
                    style={{ width: `${Math.min(100, Math.max(0, auditResult.sac_flipped_bits))}%` }}
                  />
                </div>
              </div>
            )}
            {auditResult?.before_hex && (
              <div>
                <span className="text-[var(--text-muted)]">Before:</span>
                <span className="ml-2 tabular-nums">{auditResult.before_hex}</span>
              </div>
            )}
            {auditResult?.tampered_hex && (
              <div>
                <span className="text-red-400">After:</span>
                <span className="ml-2 tabular-nums">{auditResult.tampered_hex}</span>
              </div>
            )}
            {auditResult?.error && (
              <div className="p-2 bg-[var(--bg-elevated)] rounded border-l-2 border-amber-500">
                <span className="text-amber-400">⚠ {String(auditResult.error)}</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Post-Quantum Signature Inspector (WOTS+ w=16 / XMSS) ── */}
      <div className="panel panel-specular p-4 mt-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="font-mono text-xs text-[var(--accent-primary)]">
            POST-QUANTUM SIGNATURE INSPECTOR (WOTS+ w=16 / XMSS)
          </h2>
          <div className="flex gap-2">
            <button
              onClick={handlePqSign}
              disabled={pqBusy}
              className="font-mono text-[10px] px-3 py-1 rounded bg-[var(--accent-secondary)]/15 text-[var(--accent-secondary)] hover:bg-[var(--accent-secondary)]/25 disabled:opacity-40"
            >
              {pqBusy ? '...' : '▶ PQ SIGN'}
            </button>
            <button
              onClick={handlePqVerify}
              disabled={pqBusy || !pqSign}
              className="font-mono text-[10px] px-3 py-1 rounded bg-[var(--accent-primary)]/15 text-[var(--accent-primary)] hover:bg-[var(--accent-primary)]/25 disabled:opacity-40"
            >
              {pqBusy ? '...' : '◉ PQ VERIFY + 3 ATTACKS'}
            </button>
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
          <div className="p-2 bg-[var(--bg-elevated)] rounded">
            <div className="text-[9px] text-[var(--text-muted)]">SHOR-VULNERABLE OPS</div>
            <div className="font-mono text-lg text-green-400">0</div>
            <div className="text-[9px] text-[var(--text-muted)]">Pure Hash-Based</div>
          </div>
          <div className="p-2 bg-[var(--bg-elevated)] rounded">
            <div className="text-[9px] text-[var(--text-muted)]">WOTS+ CHAINS</div>
            <div className="font-mono text-lg">67 <span className="text-[10px] text-[var(--text-muted)]">= 64 msg + 3 checksum</span></div>
            <div className="text-[9px] text-[var(--text-muted)]">w=16 (4-bit nibbles)</div>
          </div>
          <div className="p-2 bg-[var(--bg-elevated)] rounded">
            <div className="text-[9px] text-[var(--text-muted)]">XMSS MERKLE TREE</div>
            <div className="font-mono text-lg">H=4 <span className="text-[10px] text-[var(--text-muted)]">/ 16 leaves</span></div>
            <div className="text-[9px] text-[var(--text-muted)]">witness 2376 B · frame 112 B</div>
          </div>
          <div className="p-2 bg-[var(--bg-elevated)] rounded">
            <div className="text-[9px] text-[var(--text-muted)]">SECURITY</div>
            <div className="font-mono text-lg">2<sup>256</sup></div>
            <div className="text-[9px] text-[var(--text-muted)]">classical · 2^128 Grover</div>
          </div>
        </div>

        {pqSign && (
          <div className="font-mono text-[10px] space-y-2">
            <div className="flex items-center gap-2">
              <span className={pqSign.verified ? 'text-green-400' : 'text-red-400'}>
                {pqSign.verified ? '✓' : '✗'} verified
              </span>
              <span className="text-[var(--text-muted)]">|</span>
              <span>{pqSign.pq_scheme}</span>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
              <div className="p-2 bg-[var(--bg-elevated)] rounded">
                <div className="text-[9px] text-[var(--text-muted)]">WINTERNITZ CHECKSUM C</div>
                <div className="tabular-nums text-sm">{pqSign.winternitz_checksum}</div>
              </div>
              <div className="p-2 bg-[var(--bg-elevated)] rounded">
                <div className="text-[9px] text-[var(--text-muted)]">LEAF / SUBTREE</div>
                <div className="tabular-nums text-sm">{pqSign.leaf_index} / {pqSign.subtree_index}</div>
              </div>
              <div className="p-2 bg-[var(--bg-elevated)] rounded">
                <div className="text-[9px] text-[var(--text-muted)]">PQ PUBKEY ROOT (XMSS)</div>
                <div className="tabular-nums text-[9px] break-all">{pqSign.pq_pubkey_root}</div>
              </div>
              <div className="p-2 bg-[var(--bg-elevated)] rounded">
                <div className="text-[9px] text-[var(--text-muted)]">WITNESS DIGEST (256-BIT)</div>
                <div className="tabular-nums text-[9px] break-all">{pqSign.witness_digest}</div>
              </div>
            </div>
            <div className="grid grid-cols-3 gap-2">
              <div className="p-2 bg-[var(--bg-elevated)] rounded flex items-center gap-2">
                <Terminal className="w-3 h-3 text-[var(--accent-secondary)]" />
                <div>
                  <div className="text-[9px] text-[var(--text-muted)]">KEYGEN (rdtsc)</div>
                  <div className="tabular-nums">{pqSign.keygen_cycles.toLocaleString()} cyc · {pqSign.keygen_us.toFixed(1)} µs</div>
                </div>
              </div>
              <div className="p-2 bg-[var(--bg-elevated)] rounded flex items-center gap-2">
                <Terminal className="w-3 h-3 text-[var(--accent-secondary)]" />
                <div>
                  <div className="text-[9px] text-[var(--text-muted)]">SIGN (rdtsc)</div>
                  <div className="tabular-nums">{pqSign.sign_cycles.toLocaleString()} cyc · {pqSign.sign_us.toFixed(1)} µs</div>
                </div>
              </div>
              <div className={`p-2 rounded flex items-center gap-2 ${pqSign.vault_burn_verified ? 'bg-green-500/10' : 'bg-red-500/10'}`}>
                <Flame className="w-3 h-3 text-orange-400" />
                <div>
                  <div className="text-[9px] text-[var(--text-muted)]">VAULT KEY BURN</div>
                  <div className={pqSign.vault_burn_verified ? 'text-green-400' : 'text-red-400'}>
                    {pqSign.vault_burn_verified ? 'BURNED ✓' : 'LEAK ✗'}
                  </div>
                </div>
              </div>
            </div>
            <div>
              <span className="text-[var(--text-muted)]">cocoon_proof (SegPQ anchor):</span>
              <span className="ml-2 tabular-nums text-[var(--accent-secondary)]">{pqSign.cocoon_proof_hex}</span>
            </div>
          </div>
        )}

        {pqVerify && (
          <div className="font-mono text-[10px] mt-3 pt-3 border-t border-[var(--border-color,rgba(255,255,255,0.06))] space-y-1">
            <div className="mb-1 text-[var(--text-muted)]">LIVE FORGERY ATTEMPTS (all must be rejected):</div>
            {[
              ['mitm_rehash_attack_rejected', 'MITM keyless rehash (checksum recalc)'],
              ['wots_forward_chain_forgery_rejected', 'WOTS+ forward-chain forgery (Winternitz barrier)'],
              ['merkle_path_tamper_rejected', 'Merkle auth-path bit flip'],
            ].map(([key, label]) => (
              <div key={key} className="flex items-center gap-2">
                <span className={(pqVerify as any)[key] ? 'text-green-400' : 'text-red-400'}>
                  {(pqVerify as any)[key] ? '✓ REJECTED' : '✗ ACCEPTED'}
                </span>
                <span className="text-[var(--text-muted)]">— {label}</span>
              </div>
            ))}
            <div className="text-[var(--text-muted)] pt-1">
              verify wall time: {pqVerify.verify_us.toFixed(1)} µs · C = {pqVerify.winternitz_checksum}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}