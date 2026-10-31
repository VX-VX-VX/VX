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
      webSecurity: false, // Allow cleartext RPC to a user-selected local node
      allowRunningInsecureContent: true,
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