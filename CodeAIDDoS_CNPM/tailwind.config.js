/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'dark-bg': '#1a1a1a',
        'dark-card': '#2c2c2c',
        'primary-blue': '#3498db',
        'success-green': '#2ecc71',
        'danger-red': '#e74c3c',
      },
    },
  },
  plugins: [],
};