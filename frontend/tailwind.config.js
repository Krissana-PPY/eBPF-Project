/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./src/**/*.{js,ts,jsx,tsx,mdx}'],
  theme: {
    extend: {
      colors: {
        bg:       '#07090d',
        surface:  '#0c1420',
        surface2: '#111d2e',
        border:   '#1a2b40',
        accent:   '#00ddb0',
        htb:      '#f59e0b',
        noqos:    '#5b7fa6',
        muted:    '#4d6880',
        textdim:  '#c8daea',
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Cascadia Code', 'Fira Code', 'SF Mono', 'Menlo', 'monospace'],
        sans: ['Segoe UI', 'system-ui', '-apple-system', 'sans-serif'],
      },
    },
  },
  plugins: [],
};
