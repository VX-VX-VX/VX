import { useEffect, useState } from 'react'
import { useWorkspace } from '../../contexts/WorkspaceContext'
import CanvasVisualizer from './CanvasVisualizer'
import HexInspector from './HexInspector'

export default function BlockInspector({ selectedBlockHeight }: { selectedBlockHeight?: number }) {
  const { blocks } = useWorkspace()
  const [isCanvasReady, setIsCanvasReady] = useState(false)

  if (!blocks.length) {
    return (
      <div className="h-full flex items-center justify-center">
        <span className="font-mono text-sm text-[var(--text-muted)]">NO BLOCKS LOADED • CONNECT TO C++ NODE</span>
      </div>
    )
  }

  // Default to first block
  const block = blocks.find((b: any) => b.height === selectedBlockHeight) || blocks[0]

  if (!block) {
    return (
      <div className="h-full flex flex-col items-center justify-center py-8">
        <span className="text-[var(--text-muted)]">No block found</span>
        <div className="mt-4">
          <svg className="w-8 h-8 animate-spin text-[var(--accent-primary)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
            <circle cx="12" cy="12" r="10" />
            <path d="m16 12-4 4-4-4" />
          </svg>
        </div>
      </div>
    )
  }

  useEffect(() => {
    setIsCanvasReady(true)
  }, [block])

  const handlePixelSelect = (offset: number) => {
    const rows = document.querySelectorAll('#hex-table > div > div')
    rows.forEach((row: Element, idx: number) => {
      const rowOffset = idx * 16
      if (rowOffset <= offset && offset < rowOffset + 16) {
        ;(row as HTMLElement)?.scrollIntoView({ behavior: 'smooth', block: 'center' })
      }
    })
  }

  return (
    <div className="h-full flex bg-[var(--bg-primary)]">
      {/* LEFT: Canvas Visualizer (w-64) */}
      <div className="w-64 h-full border-r border-[var(--border-subtle)] bg-[var(--bg-primary)]">
        {isCanvasReady && (
          <CanvasVisualizer block={block} onPixelSelect={handlePixelSelect} />
        )}
        {!isCanvasReady && (
          <div className="h-full flex items-center justify-center text-[var(--text-muted)] text-xs">
            Loading canvas visualization...
          </div>
        )}
      </div>

      {/* RIGHT: Hex Inspector + Block Metadata */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Hex Inspector */}
        <HexInspector />

        {/* Block Metadata Separator */}
        <div className="h-px bg-[var(--border-subtle)] my-2" />

        {/* Block Metadata */}
        <div className="p-4 border-b border-[var(--border-subtle)] bg-[var(--bg-panel)]/50">
          <div className="font-mono text-xs text-[var(--text-muted)]">
            <span className="font-bold text-[var(--accent-primary)]">BLOCK HEIGHT:</span>
            <span className="ml-2">{block.height}</span>
          </div>
          <div className="font-mono text-xs text-[var(--text-muted)] mt-1">
            <span className="font-bold text-[var(--accent-primary)]">HASH:</span>
            <span className="ml-2 truncate w-48">{block.block_hash_hex.slice(0, 24)}...</span>
          </div>
          <div className="font-mono text-xs text-[var(--text-muted)] mt-1">
            <span className="font-bold text-[var(--accent-primary)]">TX COUNT:</span>
            <span className="ml-2">{block.tx_count}</span>
          </div>
          <div className="font-mono text-xs text-[var(--text-muted)] mt-1">
            <span className="font-bold text-[var(--accent-primary)]">TIMESTAMP:</span>
            <span className="ml-2">{new Date(block.timestamp * 1000).toLocaleString()}</span>
          </div>
        </div>

        {/* Transaction Summary */}
        {block.transactions && block.transactions.length > 0 && (
          <div className="p-4 bg-[var(--bg-panel)]/50">
            <div className="font-mono text-xs text-[var(--text-muted)]">
              <span className="font-bold text-[var(--accent-primary)]">TRANSACTIONS:</span>
              <span className="ml-2">{block.transactions.length} TX</span>
            </div>
          </div>
        )}

        {/* Action Buttons */}
        <div className="p-4 border-t border-[var(--border-subtle)] bg-[var(--bg-panel)]/50">
          <button
            onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
            className="w-full text-[10px] py-2 rounded"
          >
            Scroll to Genesis
          </button>
        </div>
      </div>
    </div>
  )
}