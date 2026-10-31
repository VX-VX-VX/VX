import { useEffect, useRef } from 'react'
import { Block } from '../../contexts/WorkspaceContext'

interface AttractorCanvasProps {
  block: Block | null
}

export default function AttractorCanvas({ block }: AttractorCanvasProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas || !block) return

    const ctx = canvas.getContext('2d')!
    const dpr = window.devicePixelRatio || 1
    const rect = canvas.getBoundingClientRect()
    canvas.width = rect.width * dpr
    canvas.height = rect.height * dpr
    ctx.scale(dpr, dpr)

    // Parse attractor coordinates
    const parseCoord = (hex: string) => {
      const bytes: number[] = []
      for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.slice(i, i + 2), 16))
      }
      return bytes.slice(0, 16)
    }

    const xBytes = parseCoord(block.attractor_coords.x_hex)
    const yBytes = parseCoord(block.attractor_coords.y_hex)
    const zBytes = parseCoord(block.attractor_coords.z_hex)

    const width = rect.width
    const height = rect.height
    const centerX = width / 2
    const centerY = height / 2
    const radius = Math.min(width, height) * 0.35

    // Animation state
    let angle = 0
    let orbitPhase = 0

    const animate = () => {
      ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--bg-panel').trim()
      ctx.fillRect(0, 0, width, height)

      // Background grid
      ctx.strokeStyle = getComputedStyle(document.documentElement).getPropertyValue('--border-subtle').trim()
      ctx.lineWidth = 0.5
      const gridSize = 30
      for (let x = 0; x <= width; x += gridSize) {
        ctx.beginPath()
        ctx.moveTo(x, 0)
        ctx.lineTo(x, height)
        ctx.stroke()
      }
      for (let y = 0; y <= height; y += gridSize) {
        ctx.beginPath()
        ctx.moveTo(0, y)
        ctx.lineTo(width, y)
        ctx.stroke()
      }

      // Draw coordinate axes
      ctx.strokeStyle = 'rgba(255,255,255,0.1)'
      ctx.lineWidth = 1
      ctx.beginPath()
      ctx.moveTo(centerX, 0)
      ctx.lineTo(centerX, height)
      ctx.moveTo(0, centerY)
      ctx.lineTo(width, centerY)
      ctx.stroke()

      // 3-Trunk visualization
      const trunks = [
        { bytes: xBytes, color: getComputedStyle(document.documentElement).getPropertyValue('--accent-primary').trim(), label: 'TRUNK P (X)' },
        { bytes: yBytes, color: getComputedStyle(document.documentElement).getPropertyValue('--accent-secondary').trim(), label: 'TRUNK Q (Y)' },
        { bytes: zBytes, color: '#fbbf24', label: 'TRUNK R (Z)' }
      ]

      trunks.forEach((trunk: { bytes: number[]; color: string; label: string }, ti: number) => {
        const phaseOffset = ti * Math.PI * 2 / 3
        const orbitRadius = radius * (0.5 + ti * 0.15)

        // Draw orbit path
        ctx.strokeStyle = trunk.color + '40'
        ctx.lineWidth = 1
        ctx.setLineDash([5, 5])
        ctx.beginPath()
        ctx.arc(centerX, centerY, orbitRadius, 0, Math.PI * 2)
        ctx.stroke()
        ctx.setLineDash([])

        // Draw attractor trajectory points
        for (let i = 0; i < 60; i++) {
          const t = (i / 60) * Math.PI * 2 + angle + phaseOffset
          const byteVal = trunk.bytes[i % trunk.bytes.length] as number
          const r = orbitRadius + (byteVal / 255 - 0.5) * (orbitRadius * 0.3)
          const x = centerX + r * Math.cos(t)
          const y = centerY + r * Math.sin(t)

          const alpha = 0.3 + 0.7 * (i / 60)
          ctx.fillStyle = trunk.color + Math.floor(alpha * 255).toString(16).padStart(2, '0')
          ctx.beginPath()
          ctx.arc(x, y, 2 + Math.sin(t * 3 + orbitPhase) * 1.5, 0, Math.PI * 2)
          ctx.fill()
        }

        // Current position marker
        const t = angle + phaseOffset
        const byteVal = trunk.bytes[Math.floor(angle * 10) % trunk.bytes.length] as number
        const r = orbitRadius + (byteVal / 255 - 0.5) * (orbitRadius * 0.3)
        const cx = centerX + r * Math.cos(t)
        const cy = centerY + r * Math.sin(t)

        // Glow
        const gradient = ctx.createRadialGradient(cx, cy, 0, cx, cy, 15)
        gradient.addColorStop(0, trunk.color)
        gradient.addColorStop(1, trunk.color + '00')
        ctx.fillStyle = gradient
        ctx.beginPath()
        ctx.arc(cx, cy, 15, 0, Math.PI * 2)
        ctx.fill()

        // Core
        ctx.fillStyle = trunk.color
        ctx.beginPath()
        ctx.arc(cx, cy, 6, 0, Math.PI * 2)
        ctx.fill()

        // Label
        ctx.fillStyle = trunk.color
        ctx.font = '10px JetBrains Mono, monospace'
        ctx.textAlign = 'center'
        ctx.fillText(trunk.label, cx, cy - 25)
      })

      // CRT unwrapping center
      ctx.strokeStyle = 'rgba(255,255,255,0.5)'
      ctx.lineWidth = 2
      ctx.beginPath()
      ctx.arc(centerX, centerY, 8, 0, Math.PI * 2)
      ctx.stroke()

      ctx.fillStyle = 'rgba(255,255,255,0.8)'
      ctx.font = 'bold 9px JetBrains Mono, monospace'
      ctx.textAlign = 'center'
      ctx.fillText('CRT', centerX, centerY + 3)

      // HUD
      ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--text-muted').trim()
      ctx.font = '9px JetBrains Mono, monospace'
      ctx.textAlign = 'left'
      ctx.fillText(`BLOCK #${block.height}`, 10, 18)
      ctx.fillText(`TX: ${block.tx_count}`, 10, 30)
      ctx.fillText(`UTIL: ${block.memory_layout.utilization_pct.toFixed(2)}%`, 10, 42)

      angle += 0.008
      orbitPhase += 0.02

      requestAnimationFrame(animate)
    }

    animate()
  }, [block])

  return (
    <div className="w-full h-full relative">
      <canvas ref={canvasRef} className="w-full h-full" style={{ background: 'var(--bg-primary)' }} />
      <div className="absolute bottom-2 right-2 font-mono text-[10px] text-[var(--text-muted)]">
        PHASE SPACE ORBIT
      </div>
    </div>
  )
}