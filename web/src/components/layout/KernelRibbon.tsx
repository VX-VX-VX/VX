import { useWorkspace } from '../../contexts/WorkspaceContext'
import { THEME_CONFIG_EXPORT } from '../../contexts/ThemeContext'
import { Zap, Server, Settings, Globe, ChevronDown } from 'lucide-react'
import type { Theme } from '../../contexts/ThemeContext'
import { useRpcHost } from '../../contexts/RpcHostContext'

function formatSupply(atomics: string): string {
  const n = BigInt(atomics)
  const whole = n / 100000000n
  const frac = n % 100000000n
  const wholeStr = whole.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',')
  const fracStr = frac.toString().padStart(8, '0')
  return `${wholeStr}.${fracStr}`
}

export default function KernelRibbon({ onToggleThemeDrawer, activeTheme, onThemeChange }: {
  onToggleThemeDrawer: () => void
  activeTheme: Theme
  onThemeChange: (t: Theme) => void
}) {
  const { status, connectionStatus } = useWorkspace()
  const { rpcHost, presets, selectHost, isCustomOpen, toggleCustom } = useRpcHost()

  return (
    <header className="h-16 px-4 border-b border-[var(--border-subtle)] bg-[var(--bg-panel)]/90 backdrop-blur-xl flex items-center justify-between z-50 sticky top-0">
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-3">
          <div className={`w-8 h-8 rounded flex items-center justify-center ${connectionStatus === 'online' ? 'bg-[var(--accent-primary)]/20 animate-pulse-slow' : 'bg-red-500/20'}`}>
            <Zap className="w-5 h-5 text-[var(--accent-primary)]" />
          </div>
          <div>
            <div className="font-mono text-xs tabular-nums text-[var(--accent-primary)]">
              ONLINE // POSIX SOCKET :{rpcHost.port || 8080} // MMAP ZERO-COPY
            </div>
            <div className="font-mono text-[10px] text-[var(--text-muted)]">
              {status ? `CHAIN HEIGHT: ${status.chain_height}  •  LEDGER: ${(status.ledger_bytes / 1024).toFixed(0)} KB = ${status.chain_height} × 64KB FRAMES` : 'INITIALIZING...'}
            </div>
          </div>
        </div>

        <div className="hidden md:flex items-center gap-2 ml-6 border-l border-[var(--border-subtle)] pl-6">
          <div className="flex items-center gap-1 text-[10px] text-[var(--text-muted)]">
            <Server className="w-3 h-3" /> INVARIANT
          </div>
          <div className="font-mono text-xs tabular-nums text-[var(--text-primary)] mx-2">
            {status ? `TOTAL SUPPLY: ${formatSupply(status.total_supply_atomics)} VX` : '—'}
          </div>
        </div>
      </div>

      <div className="flex items-center gap-2">
        {/* Node Connection Pill */}
        <div className="relative">
          <button
            onClick={toggleCustom}
            className="flex items-center gap-2 px-3 py-1.5 rounded bg-[var(--bg-elevated)] border border-[var(--border-subtle)] hover:border-[var(--accent-primary)]/50 transition-all"
            title="Switch RPC Host"
          >
            <Globe className="w-4 h-4 text-[var(--accent-primary)]" />
            <span className="font-mono text-[10px] text-[var(--text-primary)] max-w-[140px] truncate">
              {rpcHost.label}
            </span>
            <ChevronDown className="w-3 h-3 text-[var(--text-muted)]" />
          </button>
          {isCustomOpen && (
            <div className="absolute right-0 top-full mt-1 w-72 panel panel-specular p-3 z-50">
              <div className="font-mono text-[10px] text-[var(--text-muted)] mb-2">RPC HOST SELECTOR</div>
              {presets.map(p => (
                <button
                  key={p.id}
                  onClick={() => { selectHost(p.id); toggleCustom(); }}
                  className={`w-full text-left px-3 py-2 rounded mb-1 font-mono text-[10px] transition-all ${
                    rpcHost.id === p.id
                      ? 'bg-[var(--accent-primary)]/20 text-[var(--accent-primary)] border border-[var(--accent-primary)]'
                      : 'bg-[var(--bg-elevated)] text-[var(--text-primary)] hover:bg-[var(--bg-elevated)]/70'
                  }`}
                >
                  <div className="font-bold">{p.label}</div>
                  <div className="text-[var(--text-muted)]">{p.url}</div>
                </button>
              ))}
            </div>
          )}
        </div>

        {(['obsidian', 'aurum', 'lapis', 'arch', 'vault'] as const).map(t => (
          <button
            key={t}
            onClick={() => onThemeChange(t)}
            className={`px-3 py-1.5 text-[11px] font-mono rounded transition-all ${
              activeTheme === t
                ? 'bg-[var(--accent-primary)] text-[var(--bg-primary)] font-semibold'
                : 'text-[var(--text-muted)] hover:text-[var(--text-primary)] bg-[var(--bg-elevated)]'
            }`}
            title={THEME_CONFIG_EXPORT[t as keyof typeof THEME_CONFIG_EXPORT]?.desc}
          >
            {THEME_CONFIG_EXPORT[t as keyof typeof THEME_CONFIG_EXPORT]?.label.split(' ')[0]}
          </button>
        ))}

        <button
          onClick={onToggleThemeDrawer}
          className="btn-secondary ml-2 px-3"
          title="UI Studio (Ctrl+K)"
        >
          <Settings className="w-4 h-4 mr-1" /> CUSTOMIZE
        </button>
      </div>
    </header>
  )
}