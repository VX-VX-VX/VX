import React, { useEffect, useRef, useState } from 'react'
import { useWorkspace } from '../../contexts/WorkspaceContext'

interface Block {
  height: number
  hash: string
  memory_layout?: {
    header_bytes: number
    tx_used_bytes: number
    tx_free_bytes: number
    tail_reserved_bytes: number
    utilization_pct: number
  }
}

interface CanvasVisualizerProps {
  block: Block | null
  onPixelSelect?: (offset: number) => void
}

export default function CanvasVisualizer({ block, onPixelSelect }: CanvasVisualizerProps) {
  const { status } = useWorkspace()
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [frameData, setFrameData] = useState<Uint8Array | null>(null)
  const [hoveredPixel, setHoveredPixel] = useState<{ x: number; y: number; offset: number } | null>(null)
  const tooltipRef = useRef<HTMLDivElement>(null)

  // Build 64KB frame from memory layout
  const buildFrameFromMemoryLayout = (layout: {
    header_bytes: number
    tx_used_bytes: number
    tx_free_bytes: number
    tail_reserved_bytes: number
    utilization_pct: number
  }): Uint8Array => {
    const frame = new Uint8Array(65536)

    // Fill header area (bytes 0..471)
    // Header: 4 + 8 + 32 + 32 + 8 + 384 + 4 = 472 bytes (0..471)
    for (let i = 0; i < Math.min(layout.header_bytes, 472); i++) {
      // Default header byte values
      frame[i] = i < 4 ? 0xAA : i < 12 ? 0xBB : i < 44 ? 0xCC : i < 76 ? 0xDD : i < 84 ? 0xEE : 0x00
    }

    // Fill transaction slots (bytes 472..65431 = 580 slots * 112 bytes)
    const txStart = 472
    const txEnd = 65432

    // Mark used slots as gold/emerald, free as obsidian
    for (let i = txStart; i < txEnd; i++) {
      const slotOffset = i - txStart
      const slotIndex = Math.floor(slotOffset / 112)
      const slotPos = slotOffset % 112

      // If this slot position is within used bytes for this slot
      const usedInSlot = Math.min(112, layout.tx_used_bytes - (slotIndex * 112))
      if (slotPos < usedInSlot) {
        // Occupied slot - emerald gold: green increases with position
        const intensity = slotPos / 112
        frame[i] = Math.floor(64 + intensity * 191) // emerald range 64-255
      } else {
        // Free slot - dark obsidian
        frame[i] = 5 // very dark
      }
    }

    // Fill VortexVM Tail (bytes 65432..65535 = 104 bytes)
    const tailStart = 65432
    for (let i = tailStart; i < 65536; i++) {
      const tailOffset = i - tailStart
      // Cycle through purple/magenta based on sub-section
      if (tailOffset < 32) {
        // VM State Root area - purple
        frame[i] = 128 + (tailOffset % 128)
      } else if (tailOffset < 40) {
        // PoGW Nonce area - magenta
        frame[i] = 192 + (tailOffset % 64)
      } else if (tailOffset < 56) {
        // Bytecode area - neon purple
        frame[i] = 200 + (tailOffset % 56)
      } else {
        // Reserved
        frame[i] = 220 + (tailOffset % 36)
      }
    }

    return frame
  }

  // Get color for a byte based on its region and value
  const getByteColor = (byteValue: number, offset: number): { r: number; g: number; b: number } => {
    // Bytes 0..471: Header + 3-Trunk Galois Coords - Cyan/Electric Blue
    if (offset < 472) {
      // Electric blue intensity based on byte value
      const intensity = byteValue / 255
      // Mix from dark to bright cyan
      const base = 0x30 // dark base
      return {
        r: base + intensity * (255 - base) * 0.3,
        g: base + intensity * (255 - base) * 0.8,
        b: 255 // full blue/cyan
      }
    }
    // Bytes 472..65431: TX slots - Emerald/Gold for occupied, obsidian for free
    if (offset < 65432) {
      if (byteValue > 10) {
        // Occupied - emerald gold gradient
        const g = 50 + byteValue // emerald green
        const r = 200 + (byteValue % 50) // gold red
        const b = 20 // dark blue
        return { r, g, b }
      } else {
        // Free - dark obsidian
        return { r: 5, g: 5, b: 5 }
      }
    }
    // Bytes 65432..65535: VortexVM Tail - Neon Purple/Magenta
    return {
      r: 150 + (byteValue % 100),
      g: 30 + (byteValue % 50),
      b: 200 + (byteValue % 100)
    }
  }

  // Convert pixel coordinate to color
  const getPixelColor = (x: number, y: number): { r: number; g: number; b: number } => {
    const offset = y * 256 + x
    return getByteColor(frameData?.[offset] || 0, offset)
  }

  // Handle pixel click
  const handlePixelClick = (x: number, y: number) => {
    const offset = y * 256 + x
    onPixelSelect?.(offset)
  }

  // Handle mouse move for tooltip
  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = canvasRef.current?.getBoundingClientRect()
    if (!rect) return

    const x = e.clientX - rect.left
    const y = e.clientY - rect.top

    const canvasX = Math.min(Math.max(0, Math.floor(x)), 255)
    const canvasY = Math.min(Math.max(0, Math.floor(y)), 255)
    const offset = canvasY * 256 + canvasX

    setHoveredPixel({ x: canvasX, y: canvasY, offset })

    // Show tooltip
    if (tooltipRef.current) {
      getPixelColor(canvasX, canvasY)
      tooltipRef.current.style.left = `${e.clientX + 15}px`
      tooltipRef.current.style.top = `${e.clientY + 15}px`
      tooltipRef.current.style.display = 'block'
    }
  }

  useEffect(() => {
    if (!block || !block.memory_layout) return

    // Build initial frame
    const frame = buildFrameFromMemoryLayout(block.memory_layout)
    setFrameData(frame)

    // Subscribe to SSE block_sealed events to get fresh frame data
    const es = new EventSource(window.location.origin + '/api/events')
    es.addEventListener('block_sealed', (e) => {
      try {
        JSON.parse(e.data)
        // Update frame data when new block is sealed
        // Fetch new block data from status
        fetch(window.location.origin + '/api/blocks')
          .then(res => res.json())
          .then(blocksData => {
            if (blocksData.blocks) {
              const updatedBlock = blocksData.blocks.find((b: any) => b.height === block.height)
              if (updatedBlock && updatedBlock.memory_layout) {
                const frame = buildFrameFromMemoryLayout(updatedBlock.memory_layout)
                setFrameData(frame)
              }
            }
          })
      } catch {}
    })

    es.onopen = () => {
      // console.log('Canvas: Connected to SSE')
    }

    es.onerror = () => {
      // console.log('Canvas: SSE connection error')
      es.close()
    }

    return () => {
      es.close()
    }
  }, [block, status])

  return (
    <div className="relative">
      <canvas
        ref={canvasRef}
        className="w-64 h-64 bg-[var(--bg-primary)] border border-[var(--border-subtle)]"
        width={256}
        height={256}
        style={{ imageRendering: 'pixelated' }}
        onMouseMove={handleMouseMove}
      >
        {/* Draw pixels */}
        {frameData && (
          <React.Fragment>
            {Array.from({ length: 65536 }, (_, i) => i).map((offset) => {
              const x = offset % 256
              const y = Math.floor(offset / 256)
              const color = getByteColor(frameData[offset], offset)

              return (
                <rect
                  key={offset}
                  x={x}
                  y={y}
                  width={1}
                  height={1}
                  fill={`rgb(${color.r},${color.g},${color.b})`}
                />
              )
            })}
          </React.Fragment>
        )}

        {/* Hover tooltip */}
        {hoveredPixel && (
          <div
            ref={tooltipRef}
            className="absolute p-2 text-[9px] font-mono rounded bg-[var(--bg-elevated)]/90 border border-[var(--border-subtle)] shadow-[0_2px_10px_rgba(0,0,0,0.5)] z-20 transition-opacity"
            style={{ display: 'block' }}
          >
            <div className="text-[var(--accent-primary)] mb-1">Pixel ({hoveredPixel.x}, {hoveredPixel.y})</div>
            <div className="text-[var(--text-muted)] mb-1">Offset: 0x{hoveredPixel.offset.toString(16).padStart(4, '0').toUpperCase()}</div>
            <div className="text-[var(--accent-primary)] font-mono mb-1">Hex: {frameData?.[hoveredPixel.offset]?.toString(16).padStart(2, '0').toUpperCase() || '00'}</div>
            <div className="text-[var(--text-muted)] mb-1">Binary: {frameData?.[hoveredPixel.offset]?.toString(2).padStart(8, '0') || '00000000'}</div>
            <div className="text-[var(--text-primary)] mb-1">ASCII: {String.fromCharCode(frameData?.[hoveredPixel.offset] || 0) || '·'}</div>
            <div className="text-[var(--text-muted)]">
              Region: {hoveredPixel.offset < 472 ? 'Header + Galois Coords' :
                hoveredPixel.offset < 65432 ? 'Transaction Slots' : 'VortexVM Tail'}
            </div>
            <button
              onClick={() => handlePixelClick(hoveredPixel.x, hoveredPixel.y)}
              className="mt-1 btn-ghost text-[9px] px-2 py-1"
              title="Scroll hex table to this byte"
            >
              Scroll Hex Table
            </button>
          </div>
        )}
      </canvas>
    </div>
  )
}