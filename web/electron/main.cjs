const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let mainWindow = null;
let vxNodeProcess = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1024,
    minHeight: 768,
    backgroundColor: '#06080d',
    show: false,
    frame: false,
    titleBarStyle: 'hidden',
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      // Sandbox defaults kept intact: RPC to a user-selected node is done by
      // the main process over IPC (vx:rpc), never by disabling webSecurity —
      // the renderer stays behind the same-origin policy.
    },
    icon: path.join(__dirname, '../public/icon.png'),
  });

  // Load the Vite dev server in dev, or built files in production
  const isDev = process.env.NODE_ENV === 'development';
  const url = isDev
    ? 'http://localhost:5173'
    : `file://${path.join(__dirname, '../dist/index.html')}`;

  mainWindow.loadURL(url);

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    if (isDev) {
      mainWindow.webContents.openDevTools({ mode: 'detach' });
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  // Handle window controls
  ipcMain.on('window-minimize', () => mainWindow.minimize());
  ipcMain.on('window-maximize', () => {
    if (mainWindow.isMaximized()) mainWindow.unmaximize();
    else mainWindow.maximize();
  });
  ipcMain.on('window-close', () => mainWindow.close());
}

function startVxNode() {
  // Try to start local vx_node if available
  const nodePath = path.join(__dirname, '../../build/vx_node');
  try {
    vxNodeProcess = spawn(nodePath, ['--serve', '8088'], {
      detached: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    vxNodeProcess.stdout.on('data', (data) => {
      console.log(`[vx_node] ${data}`);
    });
    vxNodeProcess.stderr.on('data', (data) => {
      console.error(`[vx_node] ${data}`);
    });
  } catch (e) {
    console.log('[vx_node] Not found, using remote RPC');
  }
}

app.whenReady().then(() => {
  // RPC bridge: renderer asks the main process to fetch an absolute http(s)
  // URL. Node's fetch has no CORS, so cross-origin RPC works without
  // weakening the renderer. Registered once (NOT inside createWindow —
  // macOS re-activation would throw "second handler"). Hardening from the
  // security review: undici has no forbidden-header list, so the bridge
  // allowlists method GET|POST and only Accept/Content-Type — a compromised
  // renderer cannot forge Cookie/Host/Content-Length or send DELETE et al.
  const RPC_TIMEOUT_MS = 30000;
  ipcMain.handle('vx:rpc', async (_event, url, options = {}) => {
    if (typeof url !== 'string' || !/^https?:\/\//i.test(url)) {
      throw new Error('vx:rpc: absolute http(s) URL required');
    }
    const method = typeof options.method === 'string' ? options.method.toUpperCase() : 'GET';
    if (method !== 'GET' && method !== 'POST') {
      throw new Error('vx:rpc: only GET and POST are allowed');
    }
    const headers = {};
    if (options.headers && typeof options.headers === 'object') {
      for (const key of Object.keys(options.headers)) {
        const lower = String(key).toLowerCase();
        if (lower === 'accept' || lower === 'content-type') {
          headers[lower] = String(options.headers[key]);
        }
      }
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), RPC_TIMEOUT_MS);
    try {
      const res = await fetch(url, {
        method,
        headers,
        body: typeof options.body === 'string' ? options.body : undefined,
        signal: controller.signal,
        redirect: 'error',
      });
      const text = await res.text();
      return { ok: res.ok, status: res.status, statusText: res.statusText, text };
    } finally {
      clearTimeout(timer);
    }
  });

  startVxNode();
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (vxNodeProcess) {
    vxNodeProcess.kill('SIGTERM');
  }
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  if (vxNodeProcess) {
    vxNodeProcess.kill('SIGTERM');
  }
});