/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      colors: {
        vortex: {
          obsidian: '#05070b',
          cyan: '#00f0ff',
          indigo: '#6366f1',
          gold: '#f59e0b',
          copper: '#b45309',
          lapis: '#060b16',
          sapphire: '#3b82f6',
          sky: '#38bdf8',
          phosphor: '#10b981',
          amber: '#fbbf24',
          alabaster: '#f8fafc',
          graphite: '#1e293b',
          cobalt: '#1e3a8a',
        }
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scanline': 'scanline 8s linear infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        scanline: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        glow: {
          '0%': { boxShadow: '0 0 5px theme(colors.vortex.cyan), 0 0 10px theme(colors.vortex.cyan)' },
          '100%': { boxShadow: '0 0 20px theme(colors.vortex.cyan), 0 0 40px theme(colors.vortex.cyan)' },
        }
      }
    },
  },
  plugins: [],
}