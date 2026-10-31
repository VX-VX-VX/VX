import { useMemo, useState, useRef, useEffect } from 'react'
import { X, Copy, Search, ChevronLeft, ChevronRight } from 'lucide-react'
import { Transaction } from '../../contexts/WorkspaceContext'

interface HexInspectorFullProps {
  headerHex: string
  tx: Transaction | null
  onClose: () => void
}

const BYTES_PER_ROW = 16

export default function HexInspectorFull({ headerHex, tx, onClose }: HexInspectorFullProps) {
  const [viewMode, setViewMode] = useState<'header' | 'tx'>('header')
  const [hoveredByte, setHoveredByte] = useState<{ offset: number; byte: number; field: string; fullValue: string } | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [matches, setMatches] = useState<number[]>([])
  const [matchIndex, setMatchIndex] = useState(0)
  const rowRefs = useRef<(HTMLDivElement | null)[]>([])

  // Parse header bytes
  const headerBytes = useMemo(() => {
    const bytes = new Uint8Array(headerHex.length / 2)
    for (let i = 0; i < headerHex.length; i += 2) {
      bytes[i / 2] = parseInt(headerHex.slice(i, i + 2), 16)
    }
    return bytes
  }, [headerHex])

  // Build transaction bytes (112 bytes)
  const txBytes = useMemo(() => {
    if (!tx) return new Uint8Array(0)
    // Reconstruct from raw_tx_hex
    const bytes = new Uint8Array(tx.raw_tx_hex.length / 2)
    for (let i = 0; i < tx.raw_tx_hex.length; i += 2) {
      bytes[i / 2] = parseInt(tx.raw_tx_hex.slice(i, i + 2), 16)
    }
    return bytes
  }, [tx])

  const currentBytes = viewMode === 'header' ? headerBytes : txBytes
  const totalBytes = currentBytes.length

  // Field mapping for hover
  const getFieldInfo = (offset: number) => {
    if (viewMode === 'header') {
      if (offset < 4) return { field: 'magic', size: 4 }
      if (offset < 12) return { field: 'block_height', size: 8 }
      if (offset < 44) return { field: 'prev_block_hash', size: 32 }
      if (offset < 76) return { field: 'merkle_root', size: 32 }
      if (offset < 84) return { field: 'timestamp', size: 8 }
      if (offset < 468) return { field: 'attractor_coords', size: 384 }
      return { field: 'tx_count', size: 4 }
    } else {
      if (offset < 42) return { field: 'sender_nfa', size: 42 }
      if (offset < 84) return { field: 'receiver_nfa', size: 42 }
      if (offset < 100) return { field: 'amount (uint128 LE)', size: 16 }
      return { field: 'cocoon_proof', size: 12 }
    }
  }

  // Search functionality
  useEffect(() => {
    if (!searchQuery) {
      setMatches([])
      return
    }
    const query = searchQuery.toUpperCase().replace(/\s+/g, '')
    const found: number[] = []
    const hexStr = Array.from(currentBytes).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join('')
    let pos = hexStr.indexOf(query)
    while (pos !== -1) {
      found.push(Math.floor(pos / 2))
      pos = hexStr.indexOf(query, pos + 1)
    }
    setMatches(found)
    setMatchIndex(0)
  }, [searchQuery, currentBytes])

  // Scroll to match
  useEffect(() => {
    if (matches.length > 0 && rowRefs.current[Math.floor(matches[matchIndex] / BYTES_PER_ROW)]) {
      rowRefs.current[Math.floor(matches[matchIndex] / BYTES_PER_ROW)]?.scrollIntoView({ behavior: 'smooth', block: 'center' })
    }
  }, [matchIndex, matches])

  const formatByte = (b: number) => b.toString(16).padStart(2, '0').toUpperCase()
  const isPrintable = (b: number) => b >= 32 && b <= 126

  // Build full field value for hover
  const getFullFieldValue = (offset: number) => {
    const info = getFieldInfo(offset)
    const fieldBytes = currentBytes.slice(offset, offset + info.size)
    if (info.field === 'block_height' || info.field === 'timestamp' || info.field === 'tx_count') {
      let val = 0
      for (let i = fieldBytes.length - 1; i >= 0; i--) val = (val << 8) | fieldBytes[i]
      return val.toString()
    }
    if (info.field === 'amount (uint128 LE)') {
      let lo = 0, hi = 0
      for (let i = 7; i >= 0; i--) lo = (lo << 8) | fieldBytes[i]
      for (let i = 15; i >= 8; i--) hi = (hi << 8) | fieldBytes[i]
      return hi > 0 ? `${hi} << 64 | ${lo}` : lo.toString()
    }
    return Array.from(fieldBytes).map(formatByte).join(' ')
  }

  const rows = useMemo(() => {
    const rows: { offset: number; bytes: number[] }[] = []
    for (let i = 0; i < totalBytes; i += BYTES_PER_ROW) {
      rows.push({
        offset: i,
        bytes: Array.from(currentBytes.slice(i, Math.min(i + BYTES_PER_ROW, totalBytes)))
      })
    }
    return rows
  }, [currentBytes, totalBytes])

  return (
    <div className="h-full flex flex-col">
      {/* Toolbar */}
      <div className="flex items-center gap-4 p-3 border-b border-[var(--border-subtle)] bg-[var(--bg-elevated)]">
        <button onClick={onClose} className="btn-ghost p-1" title="Close">
          <X className="w-4 h-4" />
        </button>

        <div className="flex gap-1 border border-[var(--border-subtle)] rounded">
          <button
            onClick={() => setViewMode('header')}
            className={`px-3 py-1 text-[10px] font-mono rounded-l ${
              viewMode === 'header' ? 'bg-[var(--accent-primary)] text-[var(--bg-primary)]' : 'text-[var(--text-muted)]'
            }`}
          >
            BLOCK HEADER (472B)
          </button>
          <button
            onClick={() => setViewMode('tx')}
            disabled={!tx}
            className={`px-3 py-1 text-[10px] font-mono rounded-r ${
              viewMode === 'tx' ? 'bg-[var(--accent-primary)] text-[var(--bg-primary)]' : 'text-[var(--text-muted)]'
            }`}
          >
            TRANSACTION {tx ? `#${tx.index} (112B)` : '(NONE)'}
          </button>
        </div>

        <div className="flex-1" />

        <div className="relative">
          <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted)]" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Search hex (e.g. 58564336)..."
            className="input-field pl-8 w-64"
          />
          {matches.length > 0 && (
            <div className="ml-2 flex items-center gap-1 text-[10px] text-[var(--text-muted)]">
              <button onClick={() => setMatchIndex(i => (i - 1 + matches.length) % matches.length)} className="btn-ghost p-1"><ChevronLeft className="w-3 h-3" /></button>
              <span>{matchIndex + 1} / {matches.length}</span>
              <button onClick={() => setMatchIndex(i => (i + 1) % matches.length)} className="btn-ghost p-1"><ChevronRight className="w-3 h-3" /></button>
            </div>
          )}
        </div>

        <div className="font-mono text-[10px] text-[var(--text-muted)]">
          {totalBytes} BYTES • {Math.ceil(totalBytes / 16)} ROWS
        </div>
      </div>

      {/* Legend */}
      <div className="px-3 py-2 border-b border-[var(--border-subtle)] bg-[var(--bg-panel)]/50 flex gap-6 text-[10px] font-mono">
        <span className="text-[var(--accent-primary)]">█ OFFSET</span>
        <span className="text-[var(--text-primary)]">█ HEX BYTES</span>
        <span className="text-[var(--accent-secondary)]">█ ASCII</span>
        <span className="text-[var(--accent-primary)] bg-[var(--accent-primary)]/30 px-1 rounded">█ HIGHLIGHTED</span>
        <span className="text-[var(--text-muted)]">█ FIELD BOUNDARY</span>
      </div>

      {/* Hex Dump */}
      <div className="flex-1 overflow-auto p-3" style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '11px', lineHeight: '1.5' }}>
        <div className="space-y-1">
          {rows.map((row, rowIdx) => (
            <div
              key={rowIdx}
              ref={el => { rowRefs.current[rowIdx] = el }}
              className={`flex gap-4 select-none transition-colors ${
                matches.includes(row.offset) && matches[matchIndex] === row.offset
                  ? 'bg-[var(--accent-primary)]/10 ring-1 ring-[var(--accent-primary)]/50'
                  : ''
              }`}
              onMouseLeave={() => setHoveredByte(null)}
            >
              <div className="w-20 flex-shrink-0 text-right pr-2 text-[var(--text-muted)] tabular-nums">
                0x{row.offset.toString(16).padStart(4, '0').toUpperCase()}
              </div>
              <div className="flex gap-0.5 flex-1 min-w-0">
                {row.bytes.map((b, byteIdx) => {
                  const absOffset = row.offset + byteIdx
                  const isMatch = matches.includes(absOffset) && matches[matchIndex] === absOffset
                  const isHovered = hoveredByte?.offset === absOffset
                  const fieldInfo = getFieldInfo(absOffset)
                  const isFieldStart = absOffset === (() => {
                    if (viewMode === 'header') {
                      if (absOffset === 0 || absOffset === 4 || absOffset === 12 || absOffset === 44 || absOffset === 76 || absOffset === 84 || absOffset === 468) return absOffset
                    } else {
                      if (absOffset === 0 || absOffset === 42 || absOffset === 84 || absOffset === 100) return absOffset
                    }
                    return -1
                  })()

                  return (
                    <span
                      key={byteIdx}
                      className={`w-5 text-center rounded px-0.5 cursor-pointer transition-all select-none ${
                        isMatch ? 'bg-[var(--accent-primary)]/40 text-[var(--accent-primary)] ring-1 ring-[var(--accent-primary)]' :
                        isHovered ? 'bg-[var(--accent-primary)]/30 text-[var(--accent-primary)]' :
                        isFieldStart ? 'bg-[var(--accent-secondary)]/20 text-[var(--accent-secondary)]' :
                        'text-[var(--text-primary)] hover:bg-[var(--bg-elevated)]'
                      }`}
                      onMouseEnter={() => setHoveredByte({
                        offset: absOffset,
                        byte: b,
                        field: fieldInfo.field,
                        fullValue: getFullFieldValue(absOffset)
                      })}
                    >
                      {formatByte(b)}
                    </span>
                  )
                })}
                {/* Padding for incomplete rows */}
                {[...Array(BYTES_PER_ROW - row.bytes.length)].map((_, i) => (
                  <span key={i} className="w-5 text-center text-[var(--bg-primary)]">··</span>
                ))}
              </div>
              <div className="w-24 flex-shrink-0 font-mono text-[var(--accent-secondary)] select-none">
                {row.bytes.map(b => isPrintable(b) ? String.fromCharCode(b) : '·').join('')}
                {[...Array(BYTES_PER_ROW - row.bytes.length)].map((_, i) => <span key={i}> </span>)}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Hover Tooltip */}
      {hoveredByte && (
        <div className="p-3 border-t border-[var(--border-subtle)] bg-[var(--bg-elevated)] animate-fade-in">
          <div className="flex items-center gap-3 font-mono text-xs">
            <span className="text-[var(--accent-primary)]">OFFSET 0x{hoveredByte.offset.toString(16).padStart(4, '0').toUpperCase()}</span>
            <span className="text-[var(--text-muted)]">BYTE</span>
            <span className="text-[var(--accent-primary)] font-bold">{hoveredByte.byte.toString(16).padStart(2, '0').toUpperCase()}</span>
            <span className="text-[var(--text-muted)]">→</span>
            <span className="text-[var(--text-primary)]">{hoveredByte.field}</span>
            <span className="text-[var(--text-muted)] flex-1 text-right tabular-nums">{hoveredByte.fullValue}</span>
            <button
              onClick={() => navigator.clipboard.writeText(hoveredByte.fullValue)}
              className="btn-ghost p-1"
              title="Copy field value"
            >
              <Copy className="w-3 h-3" />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}