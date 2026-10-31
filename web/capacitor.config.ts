import { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'org.vxdex.sovereign',
  appName: 'Vortex Sovereign OS',
  webDir: 'dist',
  server: {
    androidScheme: 'http',
    cleartext: true, // Allow HTTP for LAN/Tailscale connections
  },
  android: {
    allowMixedContent: true,
    captureInput: true,
    webContentsDebuggingEnabled: true,
  },
  ios: {
    contentInset: 'always',
  },
  plugins: {
    CapacitorHttp: {
      enabled: true,
    },
  },
};

export default config;