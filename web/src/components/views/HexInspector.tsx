import { useState } from 'react'
import { useWorkspace } from '../../contexts/WorkspaceContext'
import { Search, ChevronLeft, ChevronRight, Copy, X } from 'lucide-react'

const BYTES_PER_ROW = 16

export default function HexInspector() {
  const { blocks, selectedBlock } = useWorkspace()
  const [viewMode, setViewMode] = useState<'header' | 'tx'>('header')
  const [hoveredByte, setHoveredByte] = useState<{ offset: number; byte: number; field: string; fullValue: string } | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState<number[]>([])
  const [currentSearchIdx, setCurrentSearchIdx] = useState(0)

  if (!blocks.length) {
    return (
      <div className="h-full flex items-center justify-center">
        <span className="font-mono text-sm text-[var(--text-muted)]">NO BLOCKS LOADED • CONNECT TO C++ NODE</span>
      </div>
    )
  }

  // Default to first block (bounds-safe fallbacks for short/malformed RPC data)
  const block = selectedBlock || blocks[0]
  const tx = block.transactions && block.transactions.length > 0 ? block.transactions[0] : { raw_tx_hex: '' }

  // Convert hex string to byte array (tolerant: odd length, invalid chars, empty input)
  const hexToBytes = (hex: string): Uint8Array => {
    const clean = (hex || '').replace(/[^0-9a-fA-F]/g, '')
    const n = Math.floor(clean.length / 2)
    const bytes = new Uint8Array(n)
    for (let i = 0; i < n; i++) {
      bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
    }
    return bytes
  }

  const headerBytes = hexToBytes(block?.raw_header_hex || '')
  const txBytes = tx ? hexToBytes(tx.raw_tx_hex || '') : new Uint8Array(0)

  const currentBytes = viewMode === 'header' ? headerBytes : txBytes

  // Field mapping (strict 112-byte TX invariant):
  //   0..41   sender (42B)  | 42..83 receiver (42B) | 84..91 amount u64 LE
  //   92..99  fee (8B u64 LE per v2 spec; legacy writers may use 4B) |
  //   100..103 nonce u32 LE | 104..111 tag / signature_anchor u64 LE
  const getFieldAtOffset = (offset: number): string => {
    if (viewMode === 'header') {
      if (offset < 4) return 'magic (4B)'
      if (offset < 12) return 'block_height (8B)'
      if (offset < 44) return 'prev_block_hash (32B)'
      if (offset < 76) return 'merkle_root (32B)'
      if (offset < 84) return 'timestamp (8B)'
      if (offset < 468) return 'attractor_coords (384B)'
      return 'tx_count (4B)'
    } else {
      if (offset < 42) return 'sender_nfa (42B)'
      if (offset < 84) return 'receiver_nfa (42B)'
      if (offset < 92) return 'amount (8B LE)'
      if (offset < 100) return 'fee (8B LE)'
      if (offset < 104) return 'nonce (4B LE)'
      if (offset < 112) return 'tag_or_sig (8B LE)'
      return 'padding'
    }
  }

  const handleSearch = () => {
    if (!searchQuery) {
      setSearchResults([])
      return
    }
    const query = searchQuery.toLowerCase().replace(/\s+/g, '')
    const hexStr = Array.from(currentBytes).map(b => b.toString(16).padStart(2, '0')).join('')
    const found: number[] = []
    let pos = hexStr.indexOf(query)
    while (pos !== -1) {
      found.push(Math.floor(pos / 2))
      pos = hexStr.indexOf(query, pos + 1)
    }
    setSearchResults(found)
    setCurrentSearchIdx(0)
    if (found.length > 0) {
      const idx = Math.floor(found[0] / BYTES_PER_ROW)
      const table = document.getElementById('hex-table')
      if (table) {
        const row = table.children[idx] as HTMLElement
        row?.scrollIntoView({ behavior: 'smooth', block: 'center' })
      }
    }
  }

  // Helper: Get full field value for hover (bounds-checked: never reads past buffer end)
  const getFullFieldValue = (offset: number): string => {
    const hdr = headerBytes
    const txb = txBytes
    const sliceHex = (buf: Uint8Array, off: number, len: number): string =>
      Array.from(buf.slice(off, Math.min(off + len, buf.length)))
        .map(b => b.toString(16).padStart(2, '0'))
        .join(' ')
    const readLE = (buf: Uint8Array, off: number, len: number): number => {
      // Bounds guard: short buffers return 0 instead of throwing
      if (buf.length < off + len) return 0
      let val = 0
      for (let i = off + len - 1; i >= off; i--) val = (val * 256) + Number(buf[i])
      return val
    }
    if (viewMode === 'header') {
      if (offset < 4) return sliceHex(hdr, offset, 4)
      if (offset < 12) return readLE(hdr, offset - (offset >= 12 ? 8 : 0), 8).toString() // height @4..11
      if (offset < 44) return sliceHex(hdr, offset, 32)
      if (offset < 76) return sliceHex(hdr, offset, 32)
      if (offset < 84) return readLE(hdr, 76, 8).toString() // timestamp @76..83
      if (offset < 468) return sliceHex(hdr, offset, 384)
      return readLE(hdr, 468, 4).toString() // tx_count @468..471
    } else {
      if (offset < 42) return sliceHex(txb, 0, 42) // full sender
      if (offset < 84) return sliceHex(txb, 42, 42) // full receiver
      if (offset < 92) {
        // amount u64 LE @84..91
        const lo = readLE(txb, 84, 8)
        return lo.toString()
      }
      if (offset < 100) {
        // fee u64 LE @92..99 (legacy 4B readers: low 32 bits hold the whole fee)
        return readLE(txb, 92, 8).toString()
      }
      if (offset < 104) return readLE(txb, 100, 4).toString() // nonce u32 LE
      if (offset < 112) return readLE(txb, 104, 8).toString() // tag_or_sig u64 LE
      return ''
    }
  }

  const rows: { offset: number; bytes: number[] }[] = []
  for (let i = 0; i < currentBytes.length; i += BYTES_PER_ROW) {
    rows.push({ offset: i, bytes: Array.from(currentBytes.slice(i, Math.min(i + BYTES_PER_ROW, currentBytes.length))) })
  }

  return (
    <div className="h-full flex flex-col bg-[var(--bg-primary)]">
      {/* Header Bar */}
      <div className="p-3 border-b border-[var(--border-subtle)] bg-[var(--bg-panel)]/80 flex items-center gap-4">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse" />
          <span className="font-mono text-xs text-[var(--text-muted)]">HEX X-RAY INSPECTOR</span>
        </div>
        <div className="flex gap-1 border border-[var(--border-subtle)] rounded overflow-hidden">
          <button
            onClick={() => setViewMode('header')}
            className={`px-3 py-1 text-[10px] font-mono transition-all ${
              viewMode === 'header'
                ? 'bg-[var(--accent-primary)] text-[var(--bg-primary)]'
                : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
            }`}
          >
            HEADER (472B)
          </button>
          <button
            onClick={() => setViewMode('tx')}
            disabled={!tx}
            className={`px-3 py-1 text-[10px] font-mono transition-all ${
              viewMode === 'tx'
                ? 'bg-[var(--accent-primary)] text-[var(--bg-primary)]'
                : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
            }`}
          >
            {tx ? `TX #${(tx as any).index ?? 0} (112B)` : 'NO TX'}
          </button>
        </div>
        <div className="flex-1" />

        <div className="relative">
          <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted)]" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSearch()}
            placeholder="Search hex bytes..."
            className="input-field w-48 pl-8"
          />
          <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted)]" />
          {searchResults.length > 0 && (
            <div className="absolute right-2 top-1/2 -translate-y-1/2 flex gap-1">
              <button
                onClick={() => setCurrentSearchIdx(i => Math.max(0, i - 1))}
                className="btn-ghost p-0.5"
              >
                <ChevronLeft className="w-3 h-3" />
              </button>
              <span className="font-mono text-[10px] text-[var(--text-muted)] tabular-nums">
                {currentSearchIdx + 1}/{searchResults.length}
              </span>
              <button
                onClick={() => setCurrentSearchIdx(i => Math.min(searchResults.length - 1, i + 1))}
                className="btn-ghost p-0.5"
              >
                <ChevronRight className="w-3 h-3" />
              </button>
            </div>
          )}
        </div>
        <button onClick={handleSearch} className="btn-secondary text-[10px] px-2 py-1">
          FIND
        </button>
      </div>

      {/* Block Metadata */}
      <div className="px-4 py-2 border-b border-[var(--border-subtle)] bg-[var(--bg-panel)]/50 flex items-center justify-between font-mono text-[10px]">
        <div className="flex items-center gap-3">
          <X
            onClick={() => console.log('Close')}
            className="w-4 h-4 cursor-pointer text-[var(--text-muted)] hover:text-[var(--accent-primary)]"
          />
          <span className="text-[var(--text-muted)]">BLOCK #{block.height}</span>
        </div>
        <div className="flex items-center gap-4">
          <span className="text-[var(--text-muted)]">HASH:</span>
          <span className="font-mono text-[var(--accent-primary)] truncate w-32">{(block.block_hash_hex || '').slice(0, 16)}...</span>
          <span className="text-[var(--text-muted)]">•</span>
          <span className="text-[var(--text-primary)] text-[10px] tabular-nums">{block.tx_count ?? 0} TX</span>
          <span className="text-[var(--text-muted)]">•</span>
          <span className="font-mono text-[10px] tabular-nums">{block.timestamp ? new Date(block.timestamp * 1000).toLocaleTimeString() : '—'}</span>
        </div>
      </div>

      {/* Column Headers */}
      <div className="px-4 py-2 border-b border-[var(--border-subtle)] flex items-center font-mono text-[10px] text-[var(--text-muted)]">
        <div className="w-20 text-right pr-4">OFFSET</div>
        <div className="flex gap-0.5 flex-1">
          {[...Array(BYTES_PER_ROW)].map((_, i) => (
            <div key={i} className="w-5 text-center" style={{ color: 'var(--text-muted)' }}>
              {i.toString(16)}
            </div>
          ))}
        </div>
        <div className="w-24 text-left pl-2">ASCII</div>
      </div>

      {/* Hex Grid */}
      <div id="hex-table" className="flex-1 overflow-auto p-2">
        <div className="space-y-1">
          {rows.map((row, rowIdx) => {
            const isHighlighted = searchResults.includes(row.offset) ||
              (searchResults.length > 0 && searchResults[currentSearchIdx] >= row.offset &&
               searchResults[currentSearchIdx] < row.offset + BYTES_PER_ROW)
            return (
              <div
                key={rowIdx}
                className={`flex items-center gap-0.5 hover:bg-[var(--bg-elevated)] transition-colors relative group ${
                  isHighlighted ? 'bg-[var(--accent-primary)]/10 ring-1 ring-[var(--accent-primary)]' : ''
                }`}
              >
                <div className="w-20 text-right pr-4 font-mono text-[10px] tabular-nums text-[var(--text-muted)]">
                  0x{row.offset.toString(16).padStart(4, '0').toUpperCase()}
                </div>
                <div className="flex gap-0.5 flex-1">
                  {row.bytes.map((b, byteIdx) => {
                    const absOffset = row.offset + byteIdx
                    const isHovered = hoveredByte?.offset === absOffset
                    const isHighlight = searchResults[currentSearchIdx] === absOffset && searchResults.length > 0
                    const field = getFieldAtOffset(absOffset)
                    const isFieldStart = (() => {
                      if (viewMode === 'header') {
                        return absOffset === 0 || absOffset === 4 || absOffset === 12 || absOffset === 44 ||
                          absOffset === 76 || absOffset === 84 || absOffset === 468
                      } else {
                        return absOffset === 0 || absOffset === 42 || absOffset === 84 || absOffset === 92 || absOffset === 100 || absOffset === 104
                      }
                    })()

                    return (
                      <span
                        key={byteIdx}
                        className={`w-5 h-5 flex items-center justify-center rounded text-[9px] font-mono transition-all relative cursor-pointer ${
                          isHovered || isHighlight
                            ? 'bg-[var(--accent-primary)]/30 text-[var(--accent-primary)] ring-1 ring-[var(--accent-primary)] z-10'
                            : isFieldStart
                            ? 'bg-[var(--accent-secondary)]/10 text-[var(--accent-secondary)]'
                            : 'text-[var(--text-primary)] hover:bg-[var(--bg-elevated)]'
                        }`}
                        onMouseEnter={() => setHoveredByte({
                          offset: absOffset,
                          byte: b,
                          field,
                          fullValue: getFullFieldValue(absOffset)
                        })}
                        onMouseLeave={() => setHoveredByte(null)}
                        onClick={() => navigator.clipboard.writeText(b.toString(16).padStart(2, '0'))}
                        title={field}
                      >
                        {b.toString(16).padStart(2, '0')}
                      </span>
                    )
                  })}
                  {/* Padding for incomplete rows */}
                  {[...Array(BYTES_PER_ROW - row.bytes.length)].map((_, i) => (
                    <span key={i} className="w-5 text-center text-[var(--bg-primary)]">··</span>
                  ))}
                </div>
                <div className="w-24 flex-shrink-0 font-mono text-[var(--accent-secondary)] select-none">
                  {row.bytes.map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '·')).join('')}
                  {[...Array(BYTES_PER_ROW - row.bytes.length)].map((_, i) => <span key={i}> </span>)}
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Hover Status Bar */}
      {hoveredByte && (
        <div className="p-2 border-t border-[var(--border-subtle)] bg-[var(--bg-elevated)]/50 flex items-center gap-4 font-mono text-xs">
          <div className="flex items-center gap-2">
            <span className="text-[var(--text-muted)]">OFFSET:</span>
            <span className="text-[var(--accent-primary)] tabular-nums">0x{hoveredByte.offset.toString(16).padStart(4, '0').toUpperCase()}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[var(--text-muted)]">VALUE:</span>
            <span className="text-[var(--accent-primary)] font-bold tabular-nums">{hoveredByte.byte.toString(16).padStart(2, '0').toUpperCase()}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[var(--text-muted)]">FIELD:</span>
            <span className="text-[var(--text-primary)]">{hoveredByte.field}</span>
          </div>
          <div className="flex-1" />
          <button
            onClick={() => navigator.clipboard.writeText(hoveredByte.byte.toString(16).padStart(2, '0'))}
            className="btn-ghost text-[10px] px-2 py-0.5"
            title="Copy byte value"
          >
            <Copy className="w-3 h-3 inline mr-1" /> COPY
          </button>
        </div>
      )}
    </div>
  )
}