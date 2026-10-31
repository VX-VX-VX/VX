import { useState, useCallback, useEffect } from 'react'
import { Radar, Split, Magnet, TreePine, Cpu, ShieldCheck } from 'lucide-react'

// ── Wire types ───────────────────────────────────────────────────────────────

interface SplitReorgReport {
  ok: boolean
  reorg_success?: boolean
  node_a_height_before?: number
  node_b_height_before?: number
  node_a_height_after?: number
  node_b_height_after?: number
  tip_hash_match?: boolean
  rolled_back_blocks?: number
  bytes_streamed?: number
  duration_us?: number
  error?: string
}

interface DandelionReport {
  ok: boolean
  stem_hops?: number
  phase?: string
  tdi_spam_annihilated?: number
  anonymity_set_size?: number
  hops?: { hop: number; cocoon_hash: string; phase: string }[]
  error?: string
}

interface GqcReport {
  ok: boolean
  block_height?: number
  share_count?: number
  validator_count?: number
  gqc_signature_agg?: string
  finalized_checkpoint_height?: number
  error?: string
}

interface MevReport {
  ok: boolean
  hamiltonian_energy_before?: number
  hamiltonian_energy_after?: number
  energy_delta_pct?: number
  ordering_canonical?: boolean
  error?: string
}

interface PipelineReport {
  ok: boolean
  tx_per_second?: number
  threshold_tx_per_second?: number
  passed?: boolean
  tdi_spam_filtered?: number
  heap_allocations?: number
  error?: string
}

interface ProveReport {
  ok: boolean
  proof_size_bytes?: number
  verified?: boolean
  error?: string
}

interface StealthReport {
  ok: boolean
  stealth_address?: string
  ring_size?: number
  real_index?: number
  key_image?: string
  error?: string
}

interface IvkScanReport {
  ok: boolean
  scanned_transactions?: number
  incoming_found?: number
  foreign_ivk_hits?: number
  error?: string
}

interface RdtscContour {
  op: string
  iterations: number
  min_cycles: number
  p50_cycles: number
  p99_cycles: number
  max_cycles: number
  cycles_per_iter: number
  estimated_ns: number
}

interface RdtscReport {
  ok: boolean
  isa?: string
  contours?: RdtscContour[]
  error?: string
}

interface VaultReport {
  ok: boolean
  final_page_state?: string
  key_lifetime_rdtsc_cycles?: number
  key_lifetime_us?: number
  hw_uuid_bound?: boolean
  error?: string
}

interface ChaosReport {
  ok: boolean
  mutated_inputs_tested?: number
  crashes?: number
  ub_detected?: number
  malformed_rejected_pct?: number
  sgmt_forgery_hits?: number
  sgmt_mutations?: number
  error?: string
}

interface PqSignReport {
  ok: boolean
  verified: boolean
  leaf_index: number
  subtree_index: number
  pq_pubkey_root: string
  cocoon_proof_hex: string
  winternitz_checksum: number
  witness_size_bytes: number
  tx_frame_bytes: number
  keygen_cycles: number
  keygen_us?: number
  sign_cycles: number
  sign_us?: number
  vault_burn_verified: boolean
}

interface PqVerifyReport {
  ok: boolean
  verified: boolean
  wots_verify_ok: boolean
  anchor_ok: boolean
  mitm_rehash_attack_rejected: boolean
  wots_forward_chain_forgery_rejected: boolean
  merkle_path_tamper_rejected: boolean
  verify_us?: number
}

// ── Component ────────────────────────────────────────────────────────────────

export default function WarRoomDeck() {
  const [split, setSplit] = useState<SplitReorgReport | null>(null)
  const [cocoon, setCocoon] = useState<DandelionReport | null>(null)
  const [gqc, setGqc] = useState<GqcReport | null>(null)
  const [mev, setMev] = useState<MevReport | null>(null)
  const [pipeline, setPipeline] = useState<PipelineReport | null>(null)
  const [proveKey, setProveKey] = useState('0xC4A05F11E17B3A92D6F84C1B5E2A9D30')
  const [prove, setProve] = useState<ProveReport | null>(null)
  const [stealth, setStealth] = useState<StealthReport | null>(null)
  const [ivk, setIvk] = useState<IvkScanReport | null>(null)
  const [rdtsc, setRdtsc] = useState<RdtscReport | null>(null)
  const [vault, setVault] = useState<VaultReport | null>(null)
  const [chaos, setChaos] = useState<ChaosReport | null>(null)
  const [pqSign, setPqSign] = useState<PqSignReport | null>(null)
  const [pqVerify, setPqVerify] = useState<PqVerifyReport | null>(null)
  const [busy, setBusy] = useState<string | null>(null)

  const call = useCallback(async <T,>(url: string, method: 'GET' | 'POST', body?: object, tag?: string): Promise<T | null> => {
    setBusy(tag ?? url)
    try {
      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: method === 'POST' ? JSON.stringify(body ?? {}) : undefined,
      })
      return (await res.json()) as T
    } catch (e) {
      console.error(`${url} failed:`, e)
      return null
    } finally {
      setBusy(null)
    }
  }, [])

  // Bare-metal telemetry refreshes live on mount.
  useEffect(() => {
    call<RdtscReport>('/api/telemetry/rdtsc', 'GET', undefined, 'rdtsc').then(d => d && setRdtsc(d))
  }, [call])

  const Section = ({ title, icon: Icon, children }: { title: string; icon: typeof Radar; children: React.ReactNode }) => (
    <section className="panel p-4">
      <h2 className="font-mono text-xs text-[var(--accent-primary)] mb-3 flex items-center gap-2">
        <Icon className="w-4 h-4" /> {title}
      </h2>
      <div className="space-y-3">{children}</div>
    </section>
  )

  const Btn = ({ label, onClick, active }: { label: string; onClick: () => void; active?: boolean }) => (
    <button
      onClick={onClick}
      disabled={busy !== null}
      className={`btn-secondary text-[10px] px-3 py-1.5 ${active ? 'opacity-60' : ''}`}
    >
      {busy && active ? '…' : label}
    </button>
  )

  const Kv = ({ k, v, good }: { k: string; v: string | number | boolean | undefined; good?: boolean }) => (
    <div className="flex justify-between font-mono text-[10px]">
      <span className="text-[var(--text-muted)]">{k}</span>
      <span className={good === undefined ? '' : good ? 'text-emerald-400' : 'text-red-400'}>{String(v ?? '—')}</span>
    </div>
  )

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <header className="p-4 border-b border-[var(--border-subtle)] panel-specular">
        <div className="flex items-center gap-3">
          <Radar className="w-5 h-5 text-[var(--accent-primary)]" />
          <div>
            <h1 className="font-mono text-sm text-[var(--accent-primary)]">SOVEREIGN WAR-ROOM DECK</h1>
            <p className="text-[10px] text-[var(--text-muted)] mt-1">
              Command bridge for Phases 31–44 — VX60, GQC, Anti-MEV, SGMT, Stealth, Vault, Chaos
            </p>
          </div>
        </div>
      </header>

      <div className="flex-1 overflow-auto p-4 grid grid-cols-1 xl:grid-cols-2 gap-4">

        {/* ── Section 1: Swarm P2P & GQC Finality ── */}
        <Section title="SWARM P2P & GQC FINALITY" icon={Split}>
          <div className="flex flex-wrap gap-2">
            <Btn label="SIMULATE SPLIT-BRAIN & O(1) REORG" active={busy === 'split'} onClick={async () => {
              const d = await call<SplitReorgReport>('/api/swarm/simulate_split_reorg', 'POST', {}, 'split')
              if (d) setSplit(d)
            }} />
            <Btn label="RELAY DANDELION++ ZK-COCOON" active={busy === 'cocoon'} onClick={async () => {
              const d = await call<DandelionReport>('/api/swarm/relay_cocoon', 'POST', {}, 'cocoon')
              if (d) setCocoon(d)
            }} />
            <Btn label="LOCK GQC FINALITY CHECKPOINT" active={busy === 'gqc'} onClick={async () => {
              const d = await call<GqcReport>('/api/consensus/finalize_gqc', 'POST', {}, 'gqc')
              if (d) setGqc(d)
            }} />
          </div>
          {split && (
            <div className="space-y-1">
              <Kv k="reorg_success" v={split.reorg_success} good={split.reorg_success} />
              <Kv k="heights A/B before" v={`${split.node_a_height_before} / ${split.node_b_height_before}`} />
              <Kv k="heights A/B after" v={`${split.node_a_height_after} / ${split.node_b_height_after}`} />
              <Kv k="tip_hash_match" v={split.tip_hash_match} good={split.tip_hash_match} />
              <Kv k="rolled back blocks" v={split.rolled_back_blocks} />
              <Kv k="VX60 bytes streamed" v={split.bytes_streamed} />
              <Kv k="duration_us" v={split.duration_us} />
            </div>
          )}
          {cocoon && (
            <div className="space-y-1">
              <Kv k="stem_hops" v={cocoon.stem_hops} />
              <Kv k="phase" v={cocoon.phase} />
              <Kv k="tdi_spam_annihilated" v={cocoon.tdi_spam_annihilated} />
              <Kv k="anonymity_set_size" v={cocoon.anonymity_set_size} />
            </div>
          )}
          {gqc && (
            <div className="space-y-1">
              <Kv k="checkpoint_height" v={gqc.finalized_checkpoint_height} good={gqc.ok} />
              <Kv k="quorum shares" v={`${gqc.share_count}/${gqc.validator_count}`} good={gqc.ok} />
              <div className="font-mono text-[10px] text-[var(--text-muted)] truncate">
                agg: {gqc.gqc_signature_agg?.slice(0, 32)}…
              </div>
            </div>
          )}
        </Section>

        {/* ── Section 2: Anti-MEV & Lock-Free Ring ── */}
        <Section title="HAMILTONIAN ANTI-MEV & LOCK-FREE RING RADAR" icon={Magnet}>
          <div className="flex flex-wrap gap-2">
            <Btn label="RUN HAMILTONIAN MEV AUDIT" active={busy === 'mev'} onClick={async () => {
              const d = await call<MevReport>('/api/mempool/mev_audit', 'POST', {}, 'mev')
              if (d) setMev(d)
            }} />
            <Btn label="BENCHMARK LOCK-FREE RING" active={busy === 'pipeline'} onClick={async () => {
              const d = await call<PipelineReport>('/api/mempool/pipeline_benchmark', 'GET', undefined, 'pipeline')
              if (d) setPipeline(d)
            }} />
          </div>
          {mev && (
            <div className="space-y-1">
              <Kv k="H before canonical sort" v={mev.hamiltonian_energy_before} />
              <Kv k="H after canonical sort" v={mev.hamiltonian_energy_after} />
              <Kv k="energy_delta_pct" v={mev.energy_delta_pct} />
              <Kv k="ordering_canonical" v={mev.ordering_canonical} good={mev.ordering_canonical} />
            </div>
          )}
          {pipeline && (
            <div className="space-y-1">
              <Kv k="throughput" v={`${(pipeline.tx_per_second ?? 0).toLocaleString()} TX/s`} good={pipeline.passed} />
              <Kv k="threshold" v={(pipeline.threshold_tx_per_second ?? 0).toLocaleString()} />
              <Kv k="tdi_spam_filtered" v={pipeline.tdi_spam_filtered} />
              <Kv k="heap_allocations" v={pipeline.heap_allocations} good={pipeline.heap_allocations === 0} />
            </div>
          )}
        </Section>

        {/* ── Section 3: SGMT & Stealth ── */}
        <Section title="SPARSE GALOIS MERKLE TRIE & STEALTH 1-OF-16" icon={TreePine}>
          <div className="flex items-center gap-2">
            <input
              value={proveKey}
              onChange={e => setProveKey(e.target.value)}
              className="flex-1 bg-transparent border border-[var(--border-subtle)] rounded px-2 py-1 font-mono text-[10px] text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-primary)]"
              placeholder="hex key for SGMT proof"
            />
            <Btn label="GENERATE & VERIFY PROOF" active={busy === 'prove'} onClick={async () => {
              const d = await call<ProveReport>('/api/state/prove', 'POST', { key: proveKey }, 'prove')
              if (d) setProve(d)
            }} />
          </div>
          {prove && (
            <div className="space-y-1">
              <Kv k="proof verified" v={prove.verified} good={prove.verified} />
              <Kv k="proof_size_bytes" v={prove.proof_size_bytes} />
            </div>
          )}
          <div className="flex flex-wrap gap-2">
            <Btn label="GEN STEALTH ENVELOPE 1-OF-16" active={busy === 'stealth'} onClick={async () => {
              const d = await call<StealthReport>('/api/zk/stealth_envelope', 'POST', {}, 'stealth')
              if (d) setStealth(d)
            }} />
            <Btn label="SCAN WITH IVK" active={busy === 'ivk'} onClick={async () => {
              const d = await call<IvkScanReport>('/api/zk/ivk_scan', 'POST', {}, 'ivk')
              if (d) setIvk(d)
            }} />
          </div>
          {stealth && (
            <div className="space-y-1">
              <Kv k="ring_size" v={stealth.ring_size} />
              <Kv k="real_index" v={stealth.real_index} />
              <div className="font-mono text-[10px] text-[var(--text-muted)] truncate">
                stealth_addr: {stealth.stealth_address?.slice(0, 28)}…
              </div>
            </div>
          )}
          {ivk && (
            <div className="space-y-1">
              <Kv k="incoming_found" v={ivk.incoming_found} good={(ivk.incoming_found ?? 0) === 1} />
              <Kv k="foreign_ivk_hits" v={ivk.foreign_ivk_hits} good={(ivk.foreign_ivk_hits ?? 0) === 0} />
              <Kv k="scanned_transactions" v={ivk.scanned_transactions} />
            </div>
          )}
        </Section>

        {/* ── Section 4: rdtsc + Vault + Chaos ── */}
        <Section title="BARE-METAL RDTSC · VAULT AIR-GAP · CHAOS FUZZER" icon={Cpu}>
          <div className="flex flex-wrap gap-2">
            <Btn label="REFRESH RDTSC TELEMETRY" active={busy === 'rdtsc'} onClick={async () => {
              const d = await call<RdtscReport>('/api/telemetry/rdtsc', 'GET', undefined, 'rdtsc')
              if (d) setRdtsc(d)
            }} />
            <Btn label="EPHEMERAL SIGN & BURN" active={busy === 'vault'} onClick={async () => {
              const d = await call<VaultReport>('/api/vault/ephemeral_sign', 'POST', {}, 'vault')
              if (d) setVault(d)
            }} />
            <Btn label="RUN CHAOS FUZZER" active={busy === 'chaos'} onClick={async () => {
              const d = await call<ChaosReport>('/api/security/chaos_fuzz', 'POST', {}, 'chaos')
              if (d) setChaos(d)
            }} />
          </div>

          {rdtsc?.contours && (
            <table className="w-full font-mono text-[9px]">
              <thead>
                <tr className="text-[var(--text-muted)] text-left">
                  <th className="py-1">CONTOUR</th>
                  <th>P50</th>
                  <th>P99</th>
                  <th>MAX</th>
                  <th className="text-right">NS</th>
                </tr>
              </thead>
              <tbody>
                {rdtsc.contours.map(c => (
                  <tr key={c.op}>
                    <td className="py-0.5 text-[var(--accent-primary)]">{c.op}</td>
                    <td>{c.p50_cycles}</td>
                    <td>{c.p99_cycles}</td>
                    <td>{c.max_cycles}</td>
                    <td className="text-right text-[var(--text-muted)]">{c.estimated_ns.toFixed(1)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {vault && (
            <div className="space-y-1">
              <Kv k="page_state" v={vault.final_page_state} good={vault.final_page_state === 'BURNED'} />
              <Kv k="key_lifetime_us" v={vault.key_lifetime_us?.toFixed(1)} />
              <Kv k="rdtsc_cycles" v={vault.key_lifetime_rdtsc_cycles?.toLocaleString()} />
              <Kv k="hw_uuid_bound" v={vault.hw_uuid_bound} good={vault.hw_uuid_bound} />
            </div>
          )}

          {chaos && (
            <div className="space-y-1">
              <Kv k="mutated_inputs_tested" v={chaos.mutated_inputs_tested?.toLocaleString()} />
              <Kv k="crashes" v={chaos.crashes} good={chaos.crashes === 0} />
              <Kv k="ub_detected" v={chaos.ub_detected} good={chaos.ub_detected === 0} />
              <Kv k="malformed_rejected_pct" v={chaos.malformed_rejected_pct} />
            </div>
          )}
        </Section>

        {/* ── Section 5: Post-Quantum WOTS+/XMSS (Phase 46) ── */}
        <Section title="POST-QUANTUM SIGNATURES · WOTS+ (w=16) + XMSS (H=4)" icon={ShieldCheck}>
          <div className="flex flex-wrap gap-2">
            <Btn label="PQ SIGN IN VAULT" active={busy === 'pq_sign'} onClick={async () => {
              const d = await call<PqSignReport>('/api/crypto/pq_sign', 'POST', { nonce: Math.floor(Math.random() * 65536) }, 'pq_sign')
              if (d) { setPqSign(d); setPqVerify(null) }
            }} />
            <Btn label="PQ VERIFY + 3 LIVE ATTACKS" active={busy === 'pq_verify'} onClick={async () => {
              const d = await call<PqVerifyReport>('/api/crypto/pq_verify', 'POST', {}, 'pq_verify')
              if (d) setPqVerify(d)
            }} />
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 font-mono text-[10px]">
            <Kv k="shor_vulnerable_ops" v={0} good />
            <Kv k="grover_security_bits" v={128} />
            <Kv k="classical_security_bits" v={256} />
            <Kv k="wots_chains" v="67 (64 msg + 3 cksum)" />
          </div>

          {pqSign && (
            <div className="space-y-1">
              <Kv k="pq_scheme" v="WOTS+ (w=16, L=67) + XMSS (H=4) over VortexSponge256" />
              <Kv k="verified" v={pqSign.verified} good={pqSign.verified} />
              <Kv k="leaf/subtree" v={`${pqSign.leaf_index} / ${pqSign.subtree_index}`} />
              <Kv k="winternitz_checksum" v={pqSign.winternitz_checksum} />
              <Kv k="witness_size_bytes" v={`${pqSign.witness_size_bytes} (frame ${pqSign.tx_frame_bytes} B)`} />
              <Kv k="pq_pubkey_root" v={pqSign.pq_pubkey_root} />
              <Kv k="cocoon_proof (SegPQ anchor)" v={pqSign.cocoon_proof_hex} />
              <div className="grid grid-cols-3 gap-2 font-mono text-[10px] pt-1">
                <Kv k="keygen" v={`${pqSign.keygen_cycles.toLocaleString()} cyc · ${pqSign.keygen_us?.toFixed(1)} µs`} />
                <Kv k="sign" v={`${pqSign.sign_cycles.toLocaleString()} cyc · ${pqSign.sign_us?.toFixed(1)} µs`} />
                <Kv k="vault_burn_verified" v={pqSign.vault_burn_verified} good={pqSign.vault_burn_verified} />
              </div>
            </div>
          )}

          {pqVerify && (
            <div className="space-y-1">
              <Kv k="wots_verify_ok" v={pqVerify.wots_verify_ok} good={pqVerify.wots_verify_ok} />
              <Kv k="anchor_ok" v={pqVerify.anchor_ok} good={pqVerify.anchor_ok} />
              <Kv k="mitm_rehash_attack_rejected" v={pqVerify.mitm_rehash_attack_rejected} good={pqVerify.mitm_rehash_attack_rejected} />
              <Kv k="wots_forward_chain_forgery_rejected" v={pqVerify.wots_forward_chain_forgery_rejected} good={pqVerify.wots_forward_chain_forgery_rejected} />
              <Kv k="merkle_path_tamper_rejected" v={pqVerify.merkle_path_tamper_rejected} good={pqVerify.merkle_path_tamper_rejected} />
              <Kv k="verify_us" v={pqVerify.verify_us?.toFixed(1)} />
            </div>
          )}
        </Section>
      </div>
    </div>
  )
}
