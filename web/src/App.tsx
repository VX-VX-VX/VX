import { ThemeProvider, useTheme } from './contexts/ThemeContext'
import { WorkspaceProvider } from './contexts/WorkspaceContext'
import { RpcHostProvider } from './contexts/RpcHostContext'
import KernelRibbon from './components/layout/KernelRibbon'
import VxAsmStudio from './components/views/VxAsmStudio'
import WarRoomDeck from './components/views/WarRoomDeck'
import DockNav from './components/layout/DockNav'
import CommandCenter from './components/views/CommandCenter'
import HexInspector from './components/views/HexInspector'
import SecuritySandbox from './components/views/SecuritySandbox'
import CryptoLab from './components/views/CryptoLab'
import VaultPanel from './components/views/VaultPanel'
import ZKMatrixPanel from './components/views/ZKMatrixPanel'
import TensorV6Lab from './components/views/TensorV6Lab'
import KernelConsole from './components/layout/KernelConsole'
import ThemeDrawer from './components/layout/ThemeDrawer'
import ErrorBoundary from './components/layout/ErrorBoundary'

function AppContent() {
  const { currentView, toggleThemeDrawer, activeTheme, toggleTheme } = useTheme()

  return (
    <div
      className={`min-h-screen flex flex-col font-sans relative overflow-x-hidden transition-colors duration-300 ${
        activeTheme === 'arch' ? 'dark' : ''
      }`}
      data-theme={activeTheme}
    >
      <KernelRibbon
        onToggleThemeDrawer={toggleThemeDrawer}
        activeTheme={activeTheme}
        onThemeChange={toggleTheme}
      />

      <DockNav />

      <main className="flex-1 overflow-hidden">
        <ErrorBoundary>
          {currentView === 'command' && <CommandCenter />}
          {currentView === 'hex' && <HexInspector />}
          {currentView === 'security' && <SecuritySandbox />}
          {currentView === 'lab' && <CryptoLab />}
          {currentView === 'vault' && <VaultPanel />}
          {currentView === 'zk_matrix' && <ZKMatrixPanel />}
          {currentView === 'tensor_v6' && <TensorV6Lab />}
          {currentView === 'asm_studio' && <VxAsmStudio />}
          {currentView === 'war_room' && <WarRoomDeck />}
        </ErrorBoundary>
      </main>

      <KernelConsole />
      <ThemeDrawer />
    </div>
  )
}

export default function App() {
  return (
    <ThemeProvider>
      <RpcHostProvider>
        <WorkspaceProvider>
          <AppContent />
        </WorkspaceProvider>
      </RpcHostProvider>
    </ThemeProvider>
  )
}