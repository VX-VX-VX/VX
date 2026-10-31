const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  // Window controls
  minimize: () => ipcRenderer.send('window-minimize'),
  maximize: () => ipcRenderer.send('window-maximize'),
  close: () => ipcRenderer.send('window-close'),
  onMaximizedChange: (callback) => {
    ipcRenderer.on('window-maximized', (_, maximized) => callback(maximized));
  },

  // RPC host configuration
  getRpcHost: () => ipcRenderer.invoke('get-rpc-host'),
  setRpcHost: (host) => ipcRenderer.invoke('set-rpc-host', host),

  // Platform info
  platform: process.platform,
  isElectron: true,
});