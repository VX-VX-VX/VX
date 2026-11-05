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

  // SSE-over-IPC relay (BACKLOG 0.17 residual): the renderer asks the main
  // process to stream /api/events; chunks are parsed into SSE frames and
  // forwarded over IPC. Same hardening as vx:rpc — absolute http(s) URL,
  // GET only, header allowlist, redirects refused. No 30 s timeout: SSE is
  // a long-lived stream; liveness is the renderer's reconnect policy.
  const sseStreams = new Map(); // webContents.id -> { controller, url }
  ipcMain.on('vx:sse-open', (event, url) => {
    if (typeof url !== 'string' || !/^https?:\/\//i.test(url)) {
      event.sender.send('vx:sse-error', { url: String(url), error: 'absolute http(s) URL required' });
      return;
    }
    // One live stream per renderer: a re-open closes the previous one.
    const prev = sseStreams.get(event.sender.id);
    if (prev) {
      try { prev.controller.abort(); } catch (_) {}
      sseStreams.delete(event.sender.id);
    }
    const controller = new AbortController();
    sseStreams.set(event.sender.id, { controller, url });
    (async () => {
      try {
        const res = await fetch(url, {
          method: 'GET',
          headers: { Accept: 'text/event-stream' },
          signal: controller.signal,
          redirect: 'error',
        });
        if (!res.ok || !res.body) {
          event.sender.send('vx:sse-closed', { url, status: res.status });
          sseStreams.delete(event.sender.id);
          return;
        }
        event.sender.send('vx:sse-open', { url, status: res.status });
        let buffer = '';
        const sendFrame = (raw) => {
          let name = 'message';
          const dataLines = [];
          for (const line of raw.split(/\r?\n/)) {
            if (line.startsWith(':')) continue; // comment/heartbeat
            if (line.startsWith('event:')) name = line.slice(6).trim();
            else if (line.startsWith('data:')) dataLines.push(line.slice(5).replace(/^ /, ''));
            // "id:" and "retry:" are not needed for this consumer
          }
          if (dataLines.length === 0) return;
          event.sender.send('vx:sse-event', { name, data: dataLines.join('\n') });
        };
        for await (const chunk of res.body) {
          buffer += Buffer.from(chunk).toString('utf8');
          const m = buffer.match(/\r?\n\r?\n/);
          while (m) {
            const raw = buffer.slice(0, m.index);
            buffer = buffer.slice(m.index + m[0].length);
            if (raw.trim().length > 0) sendFrame(raw);
            m = buffer.match(/\r?\n\r?\n/);
          }
        }
        // Server closed the stream normally.
        event.sender.send('vx:sse-closed', { url, status: res.status });
      } catch (err) {
        if (!controller.signal.aborted) {
          event.sender.send('vx:sse-closed', { url, status: 0, error: String(err) });
        }
      } finally {
        sseStreams.delete(event.sender.id);
      }
    })();
  });
  ipcMain.on('vx:sse-close', (event) => {
    const s = sseStreams.get(event.sender.id);
    if (s) {
      try { s.controller.abort(); } catch (_) {}
      sseStreams.delete(event.sender.id);
      event.sender.send('vx:sse-closed', { url: s.url, status: 0, error: 'client closed' });
    }
  });
  // Kill streams when the window navigates away or closes.
  const abortStreamsFor = (wc) => {
    const s = sseStreams.get(wc.id);
    if (s) {
      try { s.controller.abort(); } catch (_) {}
      sseStreams.delete(wc.id);
    }
  };
  mainWindow.webContents.on('did-navigate', abortStreamsFor);
  mainWindow.webContents.on('destroyed', abortStreamsFor);

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