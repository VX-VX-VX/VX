import { useEffect, useRef, useState } from 'react'
import { useWorkspace } from '../../contexts/WorkspaceContext'
import { ChevronDown, ChevronUp, Terminal } from 'lucide-react'

export default function KernelConsole() {
  const { rpcLog, connectionStatus } = useWorkspace()
  const [expanded, setExpanded] = useState(true)
  const [filter, setFilter] = useState<'all' | 'errors' | 'rpc'>('all')
  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [rpcLog])

  const filteredLogs = rpcLog.filter(log => {
    if (filter === 'errors') return log.includes('ERROR')
    if (filter === 'rpc') return log.includes('/api/')
    return true
  })

  return (
    <div className={`border-t border-[var(--border-subtle)] bg-[var(--bg-panel)]/80 backdrop-blur-xl transition-all duration-300 ${
      expanded ? 'h-40' : 'h-8'
    } flex flex-col z-40`}>
      <div
        className="flex items-center justify-between px-3 cursor-pointer select-none"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-[var(--accent-primary)]" />
          <span className="font-mono text-[10px] text-[var(--text-muted)]">KERNEL EVENT CONSOLE</span>
          <span className={`text-[9px] px-1.5 py-0.25 rounded full ${(connectionStatus === 'online') ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
            {connectionStatus.toUpperCase()}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {expanded && (
            <>
              <select
                value={filter}
                onChange={e => setFilter(e.target.value as any)}
                className="font-mono text-[10px] bg-[var(--bg-elevated)] border border-[var(--border-subtle)] rounded px-1.5 py-0.5"
              >
                <option value="all">ALL</option>
                <option value="rpc">RPC CALLS</option>
                <option value="errors">ERRORS</option>
              </select>
              <span className="font-mono text-[10px] text-[var(--text-muted)] tabular-nums">
                {filteredLogs.length} events
              </span>
            </>
          )}
          {expanded ? <ChevronDown className="w-4 h-4 text-[var(--text-muted)]" /> : <ChevronUp className="w-4 h-4 text-[var(--text-muted)]" />}
        </div>
      </div>

      {expanded && (
        <div ref={scrollRef} className="flex-1 overflow-y-auto px-3 py-1">
          {filteredLogs.length === 0 ? (
            <div className="font-mono text-[10px] text-[var(--text-muted)] py-2">
              No events logged. Make an API call to see telemetry here.
            </div>
          ) : (
            filteredLogs.map((log, i) => {
              const isError = log.includes('ERROR')
              const isStatus = log.includes('-> 200')
              return (
                <div
                  key={i}
                  className={`font-mono text-[10px] py-0.5 border-l-2 ${
                    isError
                      ? 'border-red-500/50 text-red-400'
                      : isStatus
                      ? 'border-[var(--accent-primary)]/30 text-[var(--text-primary)]'
                      : 'border-[var(--border-subtle)] text-[var(--text-muted)]'
                  }`}
                >
                  {log}
                </div>
              )
            })
          )}
        </div>
      )}
    </div>
  )
}