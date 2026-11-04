import React, { useEffect, useState } from 'react'
import { useWorkspace } from '../../contexts/WorkspaceContext'
import { useTheme } from '../../contexts/ThemeContext'
import { Send, Terminal, ArrowDownToLine } from 'lucide-react'
import AttractorCanvas from '../visualization/AttractorCanvas'
import BlockDetailPanel from '../panels/BlockDetailPanel'

// The strip renders a WINDOW of the chain, not all frames: a 1000-block
// ledger is ~1000 heavy cards and the browser chokes on the full map().
// The window grows on demand and the tip is always reachable in one click.
const STRIP_WINDOW = 50
const STRIP_WINDOW_STEP = 100

export default function CommandCenter() {
  const { blocks, accounts, selectedBlock, selectedTx, refreshAll, executeTransfer, setSelectedBlock, setSelectedTx, addRpcLog, fetchBlock } = useWorkspace()
  const { activeTheme, hashDisplay } = useTheme()
  const [transferForm, setTransferForm] = useState({ sender: '', receiver: '', amount: '' })
  const [tdiStatus, setTdiStatus] = useState<{ tdi: number; annihilated: boolean; reason: string } | null>(null)
  const [stripLimit, setStripLimit] = useState(STRIP_WINDOW)
  const [jumpHeight, setJumpHeight] = useState('')

  // Default selection: the chain TIP, once frames arrive.
  useEffect(() => {
    if (!selectedBlock && blocks.length > 0) {
      setSelectedBlock(blocks.reduce((tip, b) => (b.height > tip.height ? b : tip), blocks[0]))
    }
  }, [blocks, selectedBlock, setSelectedBlock])

  // Keep the selected frame visible in the strip (also fires on jump).
  useEffect(() => {
    if (!selectedBlock) return
    const el = document.getElementById(`frame-${selectedBlock.height}`)
    el?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
  }, [selectedBlock])

  const tipBlock = blocks.length ? blocks.reduce((tip, b) => (b.height > tip.height ? b : tip), blocks[0]) : null

  const handleJump = async () => {
    const h = parseInt(jumpHeight, 10)
    if (isNaN(h) || h < 0) return
    const target = blocks.find(b => b.height === h) ?? (await fetchBlock(h))
    if (!target) {
      addRpcLog(`Block #${h} not found on node`)
      return
    }
    setSelectedBlock(target)
    setSelectedTx(null)
  }

  useEffect(() => {
    refreshAll()
    const interval = setInterval(refreshAll, 10000)
    return () => clearInterval(interval)
  }, [refreshAll])

  useEffect(() => {
    if (transferForm.sender && transferForm.receiver && transferForm.amount) {
      const amount = parseFloat(transferForm.amount)
      if (!isNaN(amount) && amount > 0) {
        // Simulate TDI check
        const density = (amount / 112) * 10000
        const annihilated = density < 1.0
        setTdiStatus({ tdi: density, annihilated, reason: annihilated ? 'ANNIHILATED: dust attack' : 'Valid' })
      }
    } else {
      setTdiStatus(null)
    }
  }, [transferForm])

  const handleTransfer = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      await executeTransfer(transferForm.sender, transferForm.receiver, parseFloat(transferForm.amount))
      setTransferForm({ sender: '', receiver: '', amount: '' })
    } catch (err: any) {
      addRpcLog(`Transfer failed: ${err.message}`)
    }
  }

  const genesis1 = accounts.find(a => a.payload_42.startsWith('araE'))
  const genesis2 = accounts.find(a => a.payload_42.startsWith('CLIq'))
  const addr3 = accounts.find(a => a.payload_42.startsWith('iIgi'))

  return (
    <div className="h-full grid grid-cols-12 grid-rows-6 gap-4 p-4 overflow-auto">
      {/* LEFT TOP: Block strip */}
      <div className="col-span-7 row-span-3 panel panel-specular overflow-hidden flex flex-col">
        <div className="p-3 border-b border-[var(--border-subtle)] flex items-center justify-between gap-2">
          <span className="font-mono text-xs text-[var(--accent-primary)]">LEDGER.VXB FRAME STRIP</span>
          <div className="flex items-center gap-2">
            <input
              type="number"
              min={0}
              value={jumpHeight}
              onChange={e => setJumpHeight(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleJump()}
              placeholder="# height"
              className="input-field w-24 text-[10px] py-1"
            />
            <button onClick={handleJump} className="btn-secondary text-[10px] px-2 py-1">
              JUMP
            </button>
            {tipBlock && (
              <button
                onClick={() => { setSelectedBlock(tipBlock); setSelectedTx(null) }}
                className="btn-secondary text-[10px] px-2 py-1 flex items-center gap-1"
                title={`Jump to tip (block #${tipBlock.height})`}
              >
                <ArrowDownToLine className="w-3 h-3" /> TIP
              </button>
            )}
            <span className="font-mono text-[10px] text-[var(--text-muted)]">
              {blocks.length} FRAMES • {blocks.length * 64} KB
            </span>
          </div>
        </div>
        <div className="p-3 flex-1 overflow-y-auto">
          <div className="space-y-2">
            {blocks.slice().reverse().slice(0, stripLimit).map((block) => (
              <button
                key={block.height}
                id={`frame-${block.height}`}
                onClick={() => { setSelectedBlock(block); setSelectedTx(null); }}
                className={`w-full text-left p-3 rounded transition-all font-mono text-xs ${
                  selectedBlock?.height === block.height
                    ? 'bg-[var(--accent-primary)]/15 border border-[var(--accent-primary)]'
                    : 'bg-[var(--bg-elevated)] border border-[var(--border-subtle)] hover:border-[var(--accent-primary)]/50'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-bold tabular-nums">BLOCK #{block.height}</span>
                  <span className="text-[var(--text-muted)]">{block.tx_count} TX</span>
                </div>
                <div className="h-4 bg-[var(--bg-primary)] rounded overflow-hidden relative">
                  <div
                    className="absolute inset-0 bg-[var(--accent-primary)]/20"
                    style={{ width: `${block.memory_layout.utilization_pct}%` }}
                  />
                  <div className="absolute inset-0 flex items-center justify-center text-[10px] text-[var(--text-muted)]">
                    {block.memory_layout.utilization_pct.toFixed(2)}% UTIL
                  </div>
                </div>
                <div className="flex flex-wrap gap-x-2 mt-1 text-[10px] text-[var(--text-muted)]">
                  <span className="break-all">{hashDisplay === 'full' ? block.block_hash_hex : block.block_hash_hex.slice(0, 12) + '...'}</span>
                  <span>•</span>
                  <span className="tabular-nums">{new Date(block.timestamp * 1000).toLocaleTimeString()}</span>
                </div>
              </button>
            ))}
            {blocks.length > stripLimit && (
              <button
                onClick={() => setStripLimit(l => l + STRIP_WINDOW_STEP)}
                className="w-full p-2 rounded border border-[var(--border-subtle)] text-center font-mono text-[10px] text-[var(--text-muted)] hover:border-[var(--accent-primary)]/50 hover:text-[var(--text-primary)] transition-all"
              >
                SHOW OLDER FRAMES ({blocks.length - stripLimit} MORE)
              </button>
            )}
          </div>
        </div>
      </div>

      {/* RIGHT TOP: Block Detail (moved up: details first, no scrolling down) */}
      <div className="col-span-5 row-span-3 panel panel-specular overflow-hidden">
        <BlockDetailPanel block={selectedBlock} tx={selectedTx} onTxSelect={setSelectedTx} />
      </div>

      {/* LEFT BOTTOM: Attractor Canvas */}
      <div className="col-span-7 row-span-3 panel panel-specular">
        <div className="p-3 border-b border-[var(--border-subtle)] flex items-center justify-between">
          <span className="font-mono text-xs text-[var(--accent-primary)]">3-TRUNK GALOIS ATTRACTOR ORBIT</span>
          <span className="font-mono text-[10px] text-[var(--text-muted)]">
            P=2^1024-2^64-1747 • Q=2^1024-2^888-3943 • R=2^1024-2^512-267799
          </span>
        </div>
        <div className="p-3 h-[calc(100%-40px)]">
          <AttractorCanvas block={selectedBlock} />
        </div>
      </div>

      {/* RIGHT BOTTOM: Balance cards + transfer form */}
      <div className="col-span-5 row-span-3 panel panel-specular overflow-hidden flex flex-col">
        <div className="p-3 border-b border-[var(--border-subtle)]">
          <span className="font-mono text-xs text-[var(--accent-primary)]">BALANCE VAULT & EXPRESS TRANSFER</span>
        </div>
        <div className="p-3 flex-1 overflow-y-auto space-y-4">
          {/* Balance Cards */}
          <div className="grid gap-3">
            {[
              { label: 'GENESIS #1 SOVEREIGN VAULT', addr: genesis1, color: 'text-[var(--accent-primary)]' },
              { label: 'GENESIS #2 OPERATIONAL', addr: genesis2, color: 'text-[var(--accent-secondary)]' },
              { label: 'ADDRESS #3 TREASURY', addr: addr3, color: 'text-[var(--accent-primary)]' }
            ].map(v => (
              <div
                key={v.label}
                className={`p-3 rounded border ${activeTheme === 'vault' ? 'bg-[var(--bg-elevated)]' : ''}`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className={`font-mono text-[10px] ${v.color}`}>{v.label}</span>
                </div>
                <div className="font-mono tabular-nums text-lg">
                  {v.addr ? v.addr.balance_vx : '—'} VX
                </div>
                <div className="font-mono text-[10px] text-[var(--text-muted)] tabular-nums">
                  {v.addr ? v.addr.balance_atomics : '—'} ATOMICS
                </div>
              </div>
            ))}
          </div>

          {/* Transfer Form */}
          <div className="border-t border-[var(--border-subtle)] pt-4">
            <form onSubmit={handleTransfer} className="space-y-3">
              <div>
                <label className="font-mono text-[10px] text-[var(--text-muted)] block mb-1">SENDER (NFA_V6_...)</label>
                <input
                  type="text"
                  value={transferForm.sender}
                  onChange={e => setTransferForm({ ...transferForm, sender: e.target.value })}
                  className="input-field w-full"
                  placeholder="NFA_V6_CLIqoXuU6o9M9cAcFUGEWe7dsxsM8WqV0RwVQnukAA"
                />
              </div>
              <div>
                <label className="font-mono text-[10px] text-[var(--text-muted)] block mb-1">RECEIVER (NFA_V6_...)</label>
                <input
                  type="text"
                  value={transferForm.receiver}
                  onChange={e => setTransferForm({ ...transferForm, receiver: e.target.value })}
                  className="input-field w-full"
                  placeholder="NFA_V6_iIgiAC7Bohg_wrdof8Vu1y7z0T3zHB3BMxERENEMAA"
                />
              </div>
              <div>
                <label className="font-mono text-[10px] text-[var(--text-muted)] block mb-1">AMOUNT (VX)</label>
                <input
                  type="number"
                  step="0.00000001"
                  value={transferForm.amount}
                  onChange={e => setTransferForm({ ...transferForm, amount: e.target.value })}
                  className="input-field w-full"
                  placeholder="25000"
                />
              </div>

              {tdiStatus && (
                <div className={`p-2 rounded text-[10px] font-mono flex items-center gap-2 ${
                  tdiStatus.annihilated ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-green-500/20 text-green-400 border border-green-500/30'
                }`}>
                  <Terminal className="w-3 h-3" />
                  <span>TDI: {tdiStatus.tdi.toFixed(4)} • {tdiStatus.reason}</span>
                </div>
              )}

              <button type="submit" className="btn-primary w-full flex items-center justify-center gap-2" disabled={!transferForm.sender || !transferForm.receiver || !transferForm.amount}>
                <Send className="w-4 h-4" /> SIGN & APPEND 64KB FRAME
              </button>
            </form>
          </div>
        </div>
      </div>

    </div>
  )
}