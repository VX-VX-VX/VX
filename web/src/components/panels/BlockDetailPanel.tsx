import { useState } from 'react'
import { Block, Transaction } from '../../contexts/WorkspaceContext'
import { useTheme } from '../../contexts/ThemeContext'
import { Copy, Search } from 'lucide-react'
import HexInspectorFull from '../visualization/HexInspectorFull'

interface BlockDetailPanelProps {
  block: Block | null
  tx: Transaction | null
  onTxSelect: (tx: Transaction | null) => void
}

export default function BlockDetailPanel({ block, tx, onTxSelect }: BlockDetailPanelProps) {
  const [showHex, setShowHex] = useState(false)
  // Personalization: 'full' shows every hex digit by default (per-section
  // expander still available); 'short' truncates behind the expander.
  const { hashDisplay } = useTheme()
  const [showFullCoords, setShowFullCoords] = useState(hashDisplay === 'full')

  if (!block) {
    return (
      <div className="h-full flex items-center justify-center text-[var(--text-muted)]">
        <span className="font-mono text-xs">SELECT A BLOCK FROM THE STRIP</span>
      </div>
    )
  }

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <div className="p-3 border-b border-[var(--border-subtle)] flex items-center justify-between">
        <span className="font-mono text-xs text-[var(--accent-primary)]">BLOCK #{block.height} DETAIL</span>
        <button
          onClick={() => setShowHex(!showHex)}
          className="btn-secondary text-[10px] px-2 py-1"
        >
          <Search className="w-3 h-3 mr-1" />
          HEX INSPECTOR
        </button>
      </div>

      {showHex ? (
        <div className="flex-1 p-3 overflow-auto">
          <HexInspectorFull
            headerHex={block.raw_header_hex}
            tx={tx}
            onClose={() => setShowHex(false)}
          />
        </div>
      ) : (
        <div className="flex-1 p-3 overflow-auto space-y-4">
          {/* Header Fields */}
          <div className="panel border border-[var(--border-subtle)]">
            <div className="p-3 border-b border-[var(--border-subtle)] bg-[var(--bg-elevated)]">
              <span className="font-mono text-xs text-[var(--accent-primary)]">BLOCK HEADER (472 BYTES)</span>
            </div>
            <div className="p-3 space-y-2 font-mono text-xs">
              <DetailRow label="MAGIC" value={block.magic_hex} />
              <DetailRow label="HEIGHT" value={block.height.toString()} />
              <DetailRow label="TIMESTAMP" value={new Date(block.timestamp * 1000).toISOString()} />
              <DetailRow label="TX COUNT" value={block.tx_count.toString()} />
              <DetailRow label="BLOCK HASH" value={block.block_hash_hex} copyable mono />
              <DetailRow label="PREV HASH" value={block.prev_block_hash_hex} copyable mono />
              <DetailRow label="MERKLE ROOT" value={block.merkle_root_hex} copyable mono />
            </div>
            {/* Attractor coordinates: full 256-hex-digit values behind a
                toggle — truncation hides the actual data the chain commits. */}
            <div className="p-3 pt-0 space-y-2 font-mono text-xs">
              <button
                onClick={() => setShowFullCoords(!showFullCoords)}
                className="text-[10px] text-[var(--text-muted)] hover:text-[var(--accent-primary)] transition-colors"
              >
                {showFullCoords ? '▾' : '▸'} ATTRACTOR COORDINATES (X·Y·Z, 128B EACH)
              </button>
              {(['x_hex', 'y_hex', 'z_hex'] as const).map(k => {
                const v = block.attractor_coords[k]
                const expanded = showFullCoords || hashDisplay === 'full'
                return (
                  <DetailRow
                    key={k}
                    label={k.replace('_hex', '').toUpperCase() + ' COORD'}
                    value={expanded ? v : v.slice(0, 64) + '…'}
                    copyValue={v}
                    copyable
                    mono
                  />
                )
              })}
            </div>
          </div>

          {/* Memory Layout */}
          <div className="panel border border-[var(--border-subtle)]">
            <div className="p-3 border-b border-[var(--border-subtle)] bg-[var(--bg-elevated)]">
              <span className="font-mono text-xs text-[var(--accent-primary)]">MEMORY LAYOUT</span>
            </div>
            <div className="p-3 space-y-2">
              <MemoryBar label="HEADER" used={472} total={472} color="var(--accent-primary)" />
              <MemoryBar
                label={`TX USED (${block.tx_count} × 112)`}
                used={block.memory_layout.tx_used_bytes}
                total={580 * 112}
                color="var(--accent-secondary)"
              />
              <MemoryBar
                label={`TX FREE (${580 - block.tx_count} × 112)`}
                used={block.memory_layout.tx_free_bytes}
                total={580 * 112}
                color="var(--text-muted)"
              />
              <MemoryBar label="TAIL RESERVED" used={104} total={104} color="var(--text-muted)" />
            </div>
          </div>

          {/* Transactions */}
          <div className="panel border border-[var(--border-subtle)]">
            <div className="p-3 border-b border-[var(--border-subtle)] bg-[var(--bg-elevated)] flex items-center justify-between">
              <span className="font-mono text-xs text-[var(--accent-primary)]">TRANSACTIONS ({block.tx_count})</span>
            </div>
            <div className="p-3 space-y-2 max-h-64 overflow-auto">
              {(block.transactions || []).map((t, _idx) => (
                <TxRow
                  key={_idx}
                  tx={t}
                  index={_idx}
                  selected={tx?.index === _idx}
                  onClick={() => onTxSelect(t)}
                />
              ))}
              {block.tx_count === 0 && (
                <div className="text-center text-[var(--text-muted)] py-4 font-mono text-xs">
                  NO TRANSACTIONS IN THIS BLOCK
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function DetailRow({
  label,
  value,
  copyValue,
  copyable = false,
  mono = false,
}: { label: string; value: string; copyValue?: string; copyable?: boolean; mono?: boolean }) {
  return (
    <div className="flex items-start gap-2 text-[var(--text-muted)]">
      <span className="w-24 flex-shrink-0 font-bold text-[var(--text-primary)]">{label}</span>
      <span
        className={`flex-1 break-all ${mono ? 'font-mono tabular-nums' : ''} ${
          mono ? '' : 'truncate'
        }`}
      >
        {value}
      </span>
      {copyable && (
        <button
          onClick={() => navigator.clipboard.writeText(copyValue ?? value)}
          className="p-1 flex-shrink-0 hover:text-[var(--accent-primary)] transition-colors"
          title="Copy full value"
        >
          <Copy className="w-3 h-3" />
        </button>
      )}
    </div>
  )
}

function MemoryBar({ label, used, total, color }: { label: string; used: number; total: number; color: string }) {
  const pct = total > 0 ? (used / total) * 100 : 0
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-[10px]">
        <span className="font-mono text-[var(--text-muted)]">{label}</span>
        <span className="font-mono tabular-nums text-[var(--text-primary)]">{used} / {total} B</span>
      </div>
      <div className="h-2 bg-[var(--bg-primary)] rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-300"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
      </div>
    </div>
  )
}

function TxRow({ tx, index, selected, onClick }: { tx: Transaction; index: number; selected: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`w-full text-left p-2 rounded transition-all font-mono text-[10px] ${
        selected
          ? 'bg-[var(--accent-primary)]/15 border border-[var(--accent-primary)]'
          : 'bg-[var(--bg-elevated)] border border-[var(--border-subtle)] hover:border-[var(--accent-primary)]/50'
      }`}
    >
      <div className="flex items-center justify-between mb-1">
        <span className="font-bold">TX #{index}</span>
        <span className={tx.proof_valid ? 'text-green-400' : 'text-red-400'}>
          {tx.proof_valid ? '✓ VALID' : '✗ INVALID'}
        </span>
      </div>
      <div className="flex gap-2 text-[var(--text-muted)]">
        <span className="flex-1 break-all">{tx.sender_nfa}</span>
        <span className="w-4 text-center flex-shrink-0">→</span>
        <span className="flex-1 break-all">{tx.receiver_nfa}</span>
        <span className="w-20 text-right tabular-nums flex-shrink-0">{Number(tx.amount_atomics) / 1e8} VX</span>
      </div>
      <div className="text-[8px] text-[var(--text-muted)] mt-1">
        PROOF: {tx.cocoon_proof_hex}
      </div>
    </button>
  )
}