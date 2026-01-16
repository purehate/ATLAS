/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Gruvbox color palette
        gruvbox: {
          dark: '#282828',
          darker: '#1d2021',
          light: '#ebdbb2',
          green: '#98971a',
          'green-bright': '#b8bb26',
          'green-glow': '#83a598',
          orange: '#d65d0e',
          red: '#cc241d',
          blue: '#458588',
          'blue-bright': '#83a598',
          gray: '#928374',
        },
      },
      fontFamily: {
        mono: ['Courier New', 'Monaco', 'Menlo', 'monospace'],
        'hacker': ['Courier New', 'Monaco', 'Menlo', 'monospace'],
      },
      boxShadow: {
        'glow-green': '0 0 10px rgba(184, 187, 38, 0.5), 0 0 20px rgba(184, 187, 38, 0.3)',
        'glow-green-sm': '0 0 5px rgba(184, 187, 38, 0.4)',
        'glow-green-lg': '0 0 15px rgba(184, 187, 38, 0.6), 0 0 30px rgba(184, 187, 38, 0.4)',
        'retro': '4px 4px 0px rgba(184, 187, 38, 0.3)',
      },
      animation: {
        'glow-pulse': 'glow-pulse 2s ease-in-out infinite',
        'scan-line': 'scan-line 3s linear infinite',
      },
      keyframes: {
        'glow-pulse': {
          '0%, 100%': { opacity: 1, boxShadow: '0 0 10px rgba(184, 187, 38, 0.5)' },
          '50%': { opacity: 0.8, boxShadow: '0 0 20px rgba(184, 187, 38, 0.8)' },
        },
        'scan-line': {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
      },
    },
  },
  plugins: [],
}
