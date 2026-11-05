const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  // Window controls
  minimize: () => ipcRenderer.send('window-minimize'),
  maximize: () => ipcRenderer.send('window-maximize'),
  close: () => ipcRenderer.send('window-close'),
  onMaximizedChange: (callback) => {
    ipcRenderer.on('window-maximized', (_, maximized) => callback(maximized));
  },

  // RPC bridge: absolute http(s) fetches are performed by the main process
  // (no CORS there), so the renderer never needs webSecurity disabled.
  vxRpc: (url, options) => ipcRenderer.invoke('vx:rpc', url, options),

  // SSE-over-IPC relay: the main process streams /api/events and forwards
  // parsed frames; push immediacy returns without re-opening the renderer.
  vxSse: {
    open: (url) => ipcRenderer.send('vx:sse-open', url),
    close: () => ipcRenderer.send('vx:sse-close'),
    onOpen: (cb) => ipcRenderer.on('vx:sse-open', (_e, p) => cb(p)),
    onEvent: (cb) => ipcRenderer.on('vx:sse-event', (_e, p) => cb(p)),
    onClosed: (cb) => ipcRenderer.on('vx:sse-closed', (_e, p) => cb(p)),
    onError: (cb) => ipcRenderer.on('vx:sse-error', (_e, p) => cb(p)),
  },

  // RPC host configuration
  getRpcHost: () => ipcRenderer.invoke('get-rpc-host'),
  setRpcHost: (host) => ipcRenderer.invoke('set-rpc-host', host),

  // Platform info
  platform: process.platform,
  isElectron: true,
});