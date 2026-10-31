import React from 'react'

interface State {
  error: Error | null
}

/**
 * Global crash guard: a throwing view unmounts only its own subtree instead
 * of the whole React tree (which also killed the popstate routing listener
 * and left a blank page). Shows the error + a reload button.
 */
export default class ErrorBoundary extends React.Component<{ children: React.ReactNode }, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('View crashed:', error, info.componentStack)
  }

  render() {
    if (this.state.error) {
      return (
        <div className="h-full flex items-center justify-center p-8">
          <div className="panel panel-specular p-6 max-w-xl text-center">
            <h2 className="font-mono text-sm text-red-400 mb-2">VIEW CRASHED</h2>
            <p className="font-mono text-[10px] text-[var(--text-muted)] break-all mb-4">
              {this.state.error.message}
            </p>
            <div className="flex gap-2 justify-center">
              <button
                onClick={() => this.setState({ error: null })}
                className="btn-secondary text-xs px-3 py-1.5"
              >
                RETRY VIEW
              </button>
              <button onClick={() => window.location.reload()} className="btn-primary text-xs px-3 py-1.5">
                RELOAD APP
              </button>
            </div>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
