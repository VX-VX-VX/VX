import { useState } from 'react'
import { useTheme } from '../../contexts/ThemeContext'
import { useToken } from '../../contexts/TokenContext'
import { useRpcHost } from '../../contexts/RpcHostContext'
import { X, KeyRound, Lock, Unlock, AlertTriangle } from 'lucide-react'

export default function ThemeDrawer() {
  const {
    showThemeDrawer, toggleThemeDrawer, activeTheme, toggleTheme,
    glow, setGlow, density, setDensity, cornerRadius, setCornerRadius,
    bgGrid, setBgGrid, scanlines, setScanlines, hashDisplay, setHashDisplay
  } = useTheme()
  const { hasToken, setToken, clearToken, authRequired } = useToken()
  const { rpcHost } = useRpcHost()
  const [draft, setDraft] = useState('')

  // Warn loudly if the token would leave the machine: a custom non-localhost
  // host means the Bearer header rides to a remote server.
  const remoteHost = (() => {
    if (rpcHost.id === 'localhost') return false
    if (rpcHost.id === 'proxy') return false // same-origin
    try {
      const u = new URL(rpcHost.url)
      return !['localhost', '127.0.0.1', '[::1]'].includes(u.hostname) && !u.hostname.startsWith('192.168.') && !u.hostname.startsWith('10.')
    } catch { return true } // unparsable custom URL: treat as remote
  })()

  if (!showThemeDrawer) return null

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center">
      <div className="panel w-[480px] max-h-[80vh] overflow-y-auto">
        <div className="p-4 border-b border-[var(--border-subtle)] flex items-center justify-between">
          <h2 className="font-mono text-xs text-[var(--accent-primary)]">VORTEX UI STUDIO</h2>
          <button onClick={toggleThemeDrawer} className="btn-ghost p-1">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-4 space-y-6">
          {/* Theme Presets */}
          <div>
            <h3 className="font-mono text-[10px] text-[var(--text-muted)] mb-2">THEME PRESETS</h3>
            <div className="grid grid-cols-5 gap-2">
              {[
                { id: 'obsidian', name: 'Obsidian', color: '#00f0ff', bg: '#05070b' },
                { id: 'aurum', name: 'Aurum', color: '#f59e0b', bg: '#090807' },
                { id: 'lapis', name: 'Lapis', color: '#3b82f6', bg: '#060b16' },
                { id: 'arch', name: 'Arch', color: '#10b981', bg: '#000000' },
                { id: 'vault', name: 'Vault', color: '#1e3a8a', bg: '#f8fafc' },
              ].map(t => (
                <button
                  key={t.id}
                  onClick={() => toggleTheme(t.id as any)}
                  className={`p-3 rounded text-center transition-all ${
                    activeTheme === t.id
                      ? 'ring-2 ring-[var(--accent-primary)]'
                      : 'hover:ring-1 hover:ring-[var(--border-subtle)]'
                  }`}
                  style={{ backgroundColor: t.bg }}
                >
                  <div
                    className="w-6 h-6 mx-auto rounded-full animate-pulse"
                    style={{ backgroundColor: t.color }}
                  />
                  <span className="font-mono text-[9px] mt-1 block" style={{ color: t.color }}>
                    {t.name}
                  </span>
                </button>
              ))}
            </div>
          </div>

          {/* Glow Control */}
          <div>
            <h3 className="font-mono text-[10px] text-[var(--text-muted)] mb-2 flex items-center justify-between">
              <span>GLOW & SPECULAR INTENSITY</span>
              <span className="tabular-nums text-[var(--accent-primary)]">{glow}%</span>
            </h3>
            <input
              type="range"
              min="0"
              max="100"
              value={glow}
              onChange={e => setGlow(Number(e.target.value))}
              className="w-full"
              style={{
                background: `linear-gradient(90deg, var(--bg-elevated) 0%, var(--accent-primary) ${glow}%, var(--bg-elevated) ${glow}% 100%)`
              }}
            />
            <div className="flex justify-between text-[9px] text-[var(--text-muted)] font-mono">
              <span>0% STEALTH</span>
              <span>50%</span>
              <span>100% IMPLUSE</span>
            </div>
          </div>

          {/* Corner Radius */}
          <div>
            <h3 className="font-mono text-[10px] text-[var(--text-muted)] mb-2">GEOMETRY / CORNERS</h3>
            <div className="flex gap-2">
              {[
                { val: 0 as const, label: 'Brutalist Sharp' },
                { val: 6 as const, label: 'Precision Tech' },
                { val: 12 as const, label: 'Modern Smooth' },
              ].map(opt => (
                <button
                  key={opt.label}
                  onClick={() => setCornerRadius(opt.val)}
                  className={`px-3 py-1.5 text-[10px] font-mono rounded transition-all ${
                    cornerRadius === opt.val
                      ? 'bg-[var(--accent-primary)] text-[var(--bg-primary)]'
                      : 'bg-[var(--bg-elevated)] text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                  }`}
                  style={{ borderRadius: `${opt.val}px` }}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>

          {/* Density */}
          <div>
            <h3 className="font-mono text-[10px] text-[var(--text-muted)] mb-2">WORKSPACE DENSITY</h3>
            <div className="flex gap-2">
              <button
                onClick={() => setDensity('compact')}
                className={`flex-1 px-3 py-1.5 text-[10px] font-mono rounded ${
                  density === 'compact'
                    ? 'bg-[var(--accent-primary)] text-[var(--bg-primary)]'
                    : 'bg-[var(--bg-elevated)] text-[var(--text-muted)]'
                }`}
              >
                Compact (High-Density)
              </button>
              <button
                onClick={() => setDensity('comfortable')}
                className={`flex-1 px-3 py-1.5 text-[10px] font-mono rounded ${
                  density === 'comfortable'
                    ? 'bg-[var(--accent-primary)] text-[var(--bg-primary)]'
                    : 'bg-[var(--bg-elevated)] text-[var(--text-muted)]'
                }`}
              >
                Comfortable (Spacious)
              </button>
            </div>
          </div>

          {/* Background Grid */}
          <div>
            <h3 className="font-mono text-[10px] text-[var(--text-muted)] mb-2">BACKGROUND GRID</h3>
            <div className="flex gap-2">
              {[
                { id: 'dots', label: 'Dots' },
                { id: 'blueprint', label: 'Blueprint' },
                { id: 'solid', label: 'Solid' },
              ].map(opt => (
                <button
                  key={opt.id}
                  onClick={() => setBgGrid(opt.id as any)}
                  className={`flex-1 px-3 py-1.5 text-[10px] font-mono rounded ${
                    bgGrid === opt.id
                      ? 'bg-[var(--accent-primary)] text-[var(--bg-primary)]'
                      : 'bg-[var(--bg-elevated)] text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>

          {/* Hash / coordinate display mode (personalization) */}
          <div className="flex items-center justify-between">
            <h3 className="font-mono text-[10px] text-[var(--text-muted)]">HASH & COORD VIEW</h3>
            <div className="flex gap-1 border border-[var(--border-subtle)] rounded overflow-hidden">
              {(['short', 'full'] as const).map(mode => (
                <button
                  key={mode}
                  onClick={() => setHashDisplay(mode)}
                  className={`px-2 py-1 text-[10px] font-mono transition-all ${
                    hashDisplay === mode
                      ? 'bg-[var(--accent-primary)] text-[var(--bg-primary)]'
                      : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                  }`}
                >
                  {mode === 'short' ? 'SHORT' : 'FULL'}
                </button>
              ))}
            </div>
          </div>

          {/* Scanlines */}
          <div className="flex items-center justify-between">
            <h3 className="font-mono text-[10px] text-[var(--text-muted)]">SCANLINE CRT OVERLAY</h3>
            <button
              onClick={() => setScanlines(!scanlines)}
              className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                scanlines ? 'bg-[var(--accent-primary)]' : 'bg-[var(--bg-elevated)]'
              }`}
            >
              <span
                className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                  scanlines ? 'translate-x-5' : 'translate-x-1'
                }`}
              />
            </button>
          </div>

          {/* RPC access token (v0.0.7): mutating endpoints answer 401 without it */}
          <div className="border border-[var(--border-subtle)] rounded p-3 space-y-2">
            <h3 className="font-mono text-[10px] text-[var(--text-muted)] flex items-center gap-1.5">
              {hasToken ? <Lock className="w-3 h-3 text-[var(--accent-primary)]" /> : <Unlock className="w-3 h-3" />}
              RPC ACCESS TOKEN
            </h3>
            <p className="font-mono text-[9px] leading-relaxed text-[var(--text-muted)]">
              {hasToken
                ? 'TOKEN ACTIVE — attached as Authorization: Bearer to every /api call. Stored in this browser only, never logged.'
                : 'Node runs with VX_RPC_TOKEN: mutating endpoints (transfer, mempool, vault, zk) answer 401 without the token.'}
            </p>
            {authRequired && !hasToken && (
              <div className="flex items-start gap-1.5 text-[10px] font-mono text-amber-400">
                <AlertTriangle className="w-3 h-3 mt-0.5 shrink-0" />
                <span>NODE RESPONDED 401 — set the token below to unlock mutating endpoints.</span>
              </div>
            )}
            <div className="flex gap-2">
              <input
                type="password"
                value={draft}
                onChange={e => setDraft(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter' && draft.trim()) { setToken(draft); setDraft('') } }}
                placeholder={hasToken ? '•••••••••• (set) — paste to replace' : 'paste node token (VX_RPC_TOKEN)'}
                className="flex-1 font-mono text-[10px] bg-[var(--bg-elevated)] border border-[var(--border-subtle)] rounded px-2 py-1.5 outline-none focus:border-[var(--accent-primary)]/60"
                autoComplete="off"
              />
              <button
                onClick={() => { if (draft.trim()) { setToken(draft); setDraft('') } }}
                disabled={!draft.trim()}
                className="btn-ghost px-2 py-1 text-[10px] font-mono disabled:opacity-40 flex items-center gap-1"
              >
                <KeyRound className="w-3 h-3" /> SET
              </button>
              <button
                onClick={() => { clearToken(); setDraft('') }}
                disabled={!hasToken}
                className="btn-ghost px-2 py-1 text-[10px] font-mono disabled:opacity-40"
              >
                CLEAR
              </button>
            </div>
            {hasToken && remoteHost && (
              <div className="flex items-start gap-1.5 text-[10px] font-mono text-amber-400">
                <AlertTriangle className="w-3 h-3 mt-0.5 shrink-0" />
                <span>REMOTE RPC HOST — the token is sent to {rpcHost.url}. Verify you trust this endpoint.</span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}