import { useTheme } from '../../contexts/ThemeContext'
import { X } from 'lucide-react'

export default function ThemeDrawer() {
  const {
    showThemeDrawer, toggleThemeDrawer, activeTheme, toggleTheme,
    glow, setGlow, density, setDensity, cornerRadius, setCornerRadius,
    bgGrid, setBgGrid, scanlines, setScanlines
  } = useTheme()

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
        </div>
      </div>
    </div>
  )
}