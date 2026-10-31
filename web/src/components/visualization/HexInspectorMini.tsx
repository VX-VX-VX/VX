import { useMemo, useState } from 'react'
import { Transaction } from '../../contexts/WorkspaceContext'

interface HexInspectorMiniProps {
  header?: Uint8Array
  tx?: Transaction
  onByteHover?: (offset: number, field: string, value: string) => void
  onByteLeave?: () => void
  highlightedOffset?: number | null
}

export default function HexInspectorMini({ header, tx, onByteHover, onByteLeave, highlightedOffset }: HexInspectorMiniProps) {
  const [hovered, setHovered] = useState<{ offset: number; field: string; value: string } | null>(null)

  const data = useMemo(() => {
    if (tx) {
      return Array.from({ length: 7 }, (_, i) => ({
        offset: i * 16,
        bytes: Array.from({ length: 16 }, (_, j) => (i * 16 + j) < 112 ? Math.floor(Math.random() * 256) : 0),
        ascii: ''
      }))
    }
    if (header) {
      return Array.from({ length: Math.ceil(header.length / 16) }, (_, i) => {
        const start = i * 16
        const end = Math.min(start + 16, header.length)
        return {
          offset: start,
          bytes: Array.from(header.slice(start, end)),
          ascii: ''
        }
      })
    }
    return []
  }, [header, tx])

  const formatByte = (b: number) => b.toString(16).padStart(2, '0').toUpperCase()
  const isPrintable = (b: number) => b >= 32 && b <= 126

  return (
    <div className="font-mono text-[10px] overflow-auto">
      <div className="flex gap-4 text-[var(--text-muted)] mb-2">
        <span className="w-16">OFFSET</span>
        <span className="flex gap-1">
          {[...Array(16)].map((_, i) => <span key={i} className="w-5 text-center">{i.toString(16).padStart(2, '0').toUpperCase()}</span>)}
        </span>
        <span>ASCII</span>
      </div>
      <div className="space-y-1">
        {data.map((row, rowIdx) => (
          <div
            key={rowIdx}
            className="flex gap-4 select-none"
            onMouseLeave={() => { setHovered(null); onByteLeave?.() }}
          >
            <span className="w-16 text-[var(--text-muted)] tabular-nums">
              0x{row.offset.toString(16).padStart(4, '0').toUpperCase()}
            </span>
            <div className="flex gap-1">
              {row.bytes.map((b, byteIdx) => {
                const absOffset = row.offset + byteIdx
                const isHighlighted = highlightedOffset === absOffset
                const isHovered = hovered?.offset === absOffset
                return (
                  <span
                    key={byteIdx}
                    className={`w-5 text-center rounded px-0.5 cursor-pointer transition-all ${
                      isHighlighted ? 'bg-[var(--accent-primary)]/30 text-[var(--accent-primary)] ring-1 ring-[var(--accent-primary)]' :
                      isHovered ? 'bg-[var(--accent-primary)]/20 text-[var(--accent-primary)]' :
                      'text-[var(--text-primary)] hover:bg-[var(--bg-elevated)]'
                    }`}
                    onMouseEnter={() => {
                      const field = getFieldName(absOffset, header ? 'header' : 'tx')
                      const value = getFieldValue(absOffset, b, header ? 'header' : 'tx')
                      setHovered({ offset: absOffset, field, value })
                      onByteHover?.(absOffset, field, value)
                    }}
                  >
                    {formatByte(b)}
                  </span>
                )
              })}
            </div>
            <div className="font-mono">
              {row.bytes.map((b, i) => (
                <span key={i} className="w-5 text-center">
                  {isPrintable(b) ? String.fromCharCode(b) : '·'}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
      {hovered && (
        <div className="mt-2 p-2 bg-[var(--bg-elevated)] rounded border border-[var(--border-subtle)] text-[10px]">
          <span className="text-[var(--accent-primary)]">OFFSET 0x{hovered.offset.toString(16).padStart(4, '0').toUpperCase()}</span>{' '}
          <span className="text-[var(--text-muted)]">→</span>{' '}
          <span className="text-[var(--text-primary)]">{hovered.field}</span>{' '}
          <span className="text-[var(--text-muted)]">=</span>{' '}
          <span className="font-bold">{hovered.value}</span>
        </div>
      )}
    </div>
  )
}

function getFieldName(offset: number, type: 'header' | 'tx'): string {
  if (type === 'header') {
    if (offset < 4) return 'magic'
    if (offset < 12) return 'block_height'
    if (offset < 44) return 'prev_block_hash'
    if (offset < 76) return 'merkle_root'
    if (offset < 84) return 'timestamp'
    if (offset < 468) return 'attractor_coords'
    return 'tx_count'
  }
  // Transaction fields
  if (offset < 42) return 'sender_nfa'
  if (offset < 84) return 'receiver_nfa'
  if (offset < 100) return 'amount'
  return 'cocoon_proof'
}

function getFieldValue(_offset: number, byte: number, _type: 'header' | 'tx'): string {
  return byte.toString(16).padStart(2, '0').toUpperCase()
}