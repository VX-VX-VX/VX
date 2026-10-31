import { useRef, useState } from 'react'
import { useTheme, VIEW_ROUTES } from '../../contexts/ThemeContext'
import { Home, Search, Shield, FlaskRound as Flask, Lock, Key, Cpu, Code2, Radar } from 'lucide-react'

const NAV_ITEMS = [
  { id: 'command', label: 'Command Center', icon: Home, hotkey: '1' },
  { id: 'hex', label: 'Hex Inspector', icon: Search, hotkey: '2' },
  { id: 'security', label: 'Security Sandbox', icon: Shield, hotkey: '3' },
  { id: 'lab', label: 'Crypto Lab', icon: Flask, hotkey: '4' },
  { id: 'vault', label: 'Vault', icon: Lock, hotkey: '5' },
  { id: 'zk_matrix', label: 'ZK Matrix', icon: Key, hotkey: '6' },
  { id: 'tensor_v6', label: 'Tensor V6', icon: Cpu, hotkey: '7' },
  { id: 'asm_studio', label: 'VX-ASM Studio', icon: Code2, hotkey: '8' },
  { id: 'war_room', label: 'War Room', icon: Radar, hotkey: '9' },
]

// Geometry of the hidden rail (px)
const RAIL_WIDTH = 56  // panel width when visible
const PEEK = 6         // visible sliver of the hidden panel (the glowing edge)
const EDGE_ZONE = 14   // hover strip at the left edge that summons the dock

export default function DockNav() {
  const { currentView, switchView } = useTheme()
  const [open, setOpen] = useState(false)
  const hideTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const summon = () => {
    if (hideTimer.current) clearTimeout(hideTimer.current)
    setOpen(true)
  }
  const scheduleHide = () => {
    if (hideTimer.current) clearTimeout(hideTimer.current)
    hideTimer.current = setTimeout(() => setOpen(false), 180)
  }

  return (
    <div
      className="fixed left-0 top-1/2 -translate-y-1/2 z-40 pointer-events-none"
      style={{ width: RAIL_WIDTH, height: '70vh', maxHeight: 620 }}
    >
      {/* Invisible edge sensor — the shell is pointer-events-none, only this
          strip catches the cursor approaching the left screen edge */}
      <div
        className="absolute left-0 top-0 h-full"
        style={{ width: EDGE_ZONE, pointerEvents: open ? 'none' : 'auto' }}
        onMouseEnter={summon}
        onMouseLeave={scheduleHide}
      />

      {/* The dock itself — slides out; a thin glowing sliver stays peeking.
          The sliver is itself a hover target, so it can be summoned without
          touching the very edge. */}
      <div
        className="absolute top-1/2 -translate-y-1/2 pointer-events-auto transition-transform duration-300 ease-out"
        style={{ transform: open ? 'translateX(0px)' : `translateX(${-(RAIL_WIDTH - PEEK)}px)` }}
        onMouseEnter={summon}
        onMouseLeave={scheduleHide}
      >
        <div className="panel panel-specular flex flex-col p-2 gap-2 relative">
          {/* Edge indicator line, always visible */}
          <div
            className="absolute -right-[2px] top-1/2 -translate-y-1/2 w-[2px] rounded-full transition-all duration-300"
            style={{
              height: open ? '40%' : '24%',
              background: 'linear-gradient(to bottom, transparent, var(--accent-primary), transparent)',
              opacity: open ? 0.25 : 0.8,
              boxShadow: '0 0 8px var(--accent-primary)',
            }}
          />
          {NAV_ITEMS.map(item => {
            const Icon = item.icon
            const active = currentView === item.id
            const href = VIEW_ROUTES[item.id as keyof typeof VIEW_ROUTES]
            return (
              <a
                key={item.id}
                href={href}
                onClick={e => {
                  // SPA navigation: pushState instead of full page reload
                  e.preventDefault()
                  switchView(item.id as any)
                }}
                className={`relative flex items-center justify-center w-10 h-10 rounded transition-all ${
                  active
                    ? 'bg-[var(--accent-primary)] text-[var(--bg-primary)] ring-2 ring-[var(--accent-primary)]/50'
                    : 'text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-elevated)]'
                }`}
                title={`${item.label} (${item.hotkey})`}
              >
                <Icon className="w-4 h-4" />
                <kbd
                  className={`absolute -bottom-1 -right-1 text-[8px] font-mono px-1 rounded opacity-60 ${
                    active ? 'bg-[var(--bg-primary)] text-[var(--accent-primary)]' : 'bg-[var(--bg-elevated)] text-[var(--text-muted)]'
                  }`}
                >
                  {item.hotkey}
                </kbd>
              </a>
            )
          })}
        </div>
      </div>
    </div>
  )
}
