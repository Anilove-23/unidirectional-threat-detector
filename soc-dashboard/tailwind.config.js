/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        // Base surfaces — cool slate-navy, not pure black
        surface: {
          0: '#080B10',   // app background
          1: '#0D1219',   // panel background
          2: '#121826',   // raised panel / header
          3: '#1A2233',   // hover / active surface
        },
        border: {
          DEFAULT: '#1E2733',
          strong: '#2A3547',
        },
        ink: {
          primary: '#E6EBF2',
          secondary: '#93A1B4',
          muted: '#5C6B80',
        },
        // Functional signal color (connection / live state) — teal, deliberately
        // distinct from severity reds/ambers so "live" never reads as an alert.
        signal: {
          DEFAULT: '#2DD4BF',
          dim: '#1B7F73',
        },
        // Severity scale
        sev: {
          critical: '#E5484D',
          criticalBg: 'rgba(229, 72, 77, 0.12)',
          high: '#F2994A',
          highBg: 'rgba(242, 153, 74, 0.12)',
          medium: '#E8C547',
          mediumBg: 'rgba(232, 197, 71, 0.12)',
          low: '#5B8DEF',
          lowBg: 'rgba(91, 141, 239, 0.12)',
        },
      },
      fontFamily: {
        sans: ['"IBM Plex Sans"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      boxShadow: {
        panel: '0 1px 0 0 rgba(255,255,255,0.03) inset, 0 8px 24px -12px rgba(0,0,0,0.5)',
      },
      keyframes: {
        pulseDot: {
          '0%, 100%': { opacity: 1 },
          '50%': { opacity: 0.35 },
        },
        slideIn: {
          from: { opacity: 0, transform: 'translateY(-6px)' },
          to: { opacity: 1, transform: 'translateY(0)' },
        },
        travel: {
          '0%': { transform: 'translateX(0)', opacity: 0 },
          '10%': { opacity: 1 },
          '90%': { opacity: 1 },
          '100%': { transform: 'translateX(calc(100% - 8px))', opacity: 0 },
        },
      },
      animation: {
        pulseDot: 'pulseDot 1.8s ease-in-out infinite',
        slideIn: 'slideIn 0.22s ease-out',
        travel: 'travel 2.4s linear infinite',
      },
    },
  },
  plugins: [],
}
