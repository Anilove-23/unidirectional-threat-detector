/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        surface: {
          0: '#0A0D14',
          1: '#0F1623',
          2: '#141D2E',
          3: '#1C2537',
          4: '#232E42',
        },
        border: {
          DEFAULT: '#1E2D45',
          strong: '#273750',
        },
        ink: {
          primary: '#E2E8F2',
          secondary: '#8898B0',
          muted: '#4A5A72',
        },
        accent: {
          DEFAULT: '#3B7ADB',
          hover: '#5090F0',
          dim: 'rgba(59,122,219,0.12)',
        },
        signal: {
          DEFAULT: '#34D399',
          dim: 'rgba(52,211,153,0.12)',
        },
        sev: {
          critical: '#F04A5A',
          criticalBg: 'rgba(240,74,90,0.08)',
          criticalBorder: 'rgba(240,74,90,0.25)',
          high: '#F59E0B',
          highBg: 'rgba(245,158,11,0.08)',
          highBorder: 'rgba(245,158,11,0.25)',
          medium: '#FBBF24',
          mediumBg: 'rgba(251,191,36,0.08)',
          mediumBorder: 'rgba(251,191,36,0.2)',
          low: '#60A5FA',
          lowBg: 'rgba(96,165,250,0.08)',
          lowBorder: 'rgba(96,165,250,0.2)',
        },
      },
      fontFamily: {
        sans: ['"Inter"', '"IBM Plex Sans"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"IBM Plex Mono"', 'ui-monospace', 'monospace'],
      },
      fontSize: {
        '2xs': ['10px', '14px'],
      },
      boxShadow: {
        card: '0 1px 3px rgba(0,0,0,0.5)',
        elevated: '0 4px 20px rgba(0,0,0,0.4)',
        modal: '0 8px 40px rgba(0,0,0,0.6)',
      },
      keyframes: {
        pulseDot: {
          '0%, 100%': { opacity: 1 },
          '50%': { opacity: 0.3 },
        },
        slideIn: {
          from: { opacity: 0, transform: 'translateY(-4px)' },
          to: { opacity: 1, transform: 'translateY(0)' },
        },
        fadeUp: {
          from: { opacity: 0, transform: 'translateY(8px)' },
          to: { opacity: 1, transform: 'translateY(0)' },
        },
        travel: {
          '0%': { transform: 'translateX(0)', opacity: 0 },
          '15%': { opacity: 1 },
          '85%': { opacity: 1 },
          '100%': { transform: 'translateX(calc(100% - 6px))', opacity: 0 },
        },
      },
      animation: {
        pulseDot: 'pulseDot 2s ease-in-out infinite',
        slideIn: 'slideIn 0.18s ease-out',
        fadeUp: 'fadeUp 0.25s ease-out',
        travel: 'travel 2.4s linear infinite',
      },
    },
  },
  plugins: [],
}
