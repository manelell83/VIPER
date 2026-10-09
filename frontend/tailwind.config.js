/** @type {import('tailwindcss').Config} */

// VIPER brand ramps. They REPLACE Tailwind's default red / orange / yellow /
// green / blue / gray / slate, so every existing utility (text-red-400,
// bg-blue-900/40, ...) automatically uses the VIPER palette:
//   red    -> crimson (accent, CRITICAL)      orange -> ember (HIGH)
//   yellow -> gold (MEDIUM, warning)          green  -> success
//   blue   -> steel (LOW, informational)      gray / slate -> warm ink neutrals
const crimson = {
  50: "#fdf2f4", 100: "#fbe3e7", 200: "#f6c3cc", 300: "#ef93a3", 400: "#f0566b",
  500: "#e4324f", 600: "#c01f3c", 700: "#9f1932", 800: "#80162b", 900: "#5e1222", 950: "#3a0913",
};
const ember = {
  50: "#fdf4ee", 100: "#fbe4d4", 200: "#f6c4a5", 300: "#f09c6d", 400: "#ea7a45",
  500: "#dc5f28", 600: "#b94a1c", 700: "#933a18", 800: "#742f17", 900: "#5a2614", 950: "#321208",
};
const gold = {
  50: "#fbf7ea", 100: "#f5ebc8", 200: "#ead58f", 300: "#ddbb54", 400: "#cfa22c",
  500: "#b8860b", 600: "#9a6f09", 700: "#7a5a06", 800: "#5f4608", 900: "#4a370a", 950: "#2a1f04",
};
const success = {
  50: "#eef8f1", 100: "#d5efdc", 200: "#a9deb9", 300: "#6fd194", 400: "#3fbf6a",
  500: "#24994c", 600: "#1a7a3a", 700: "#166331", 800: "#144f29", 900: "#113f22", 950: "#082313",
};
const steel = {
  50: "#f1f4f8", 100: "#dfe6ef", 200: "#c0cddd", 300: "#98abc4", 400: "#7690b0",
  500: "#5b7699", 600: "#485f7e", 700: "#3b4d66", 800: "#313f53", 900: "#2a3545", 950: "#1a212c",
};
const ink = {
  50: "#f7f5f2", 100: "#efece7", 200: "#dedad3", 300: "#c4bfb7", 400: "#9a958f",
  500: "#77737c", 600: "#5a5660", 700: "#3f3c45", 800: "#2a2830", 900: "#1b1a20", 950: "#111015",
};

export default {
  content: ["./index.html", "./src/**/*.{js,jsx,ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        red: crimson,
        orange: ember,
        yellow: gold,
        green: success,
        blue: steel,
        gray: ink,
        slate: ink,
        ink,
        cream: { DEFAULT: "#f2ece3", 2: "#e9e1d4", paper: "#fbf8f3" },
        // Theme-aware colours (CSS variables, switch with dark / light)
        accent: {
          DEFAULT: "var(--accent)",
          hover: "var(--accent-hover)",
          text: "var(--accent-text)",
          soft: "var(--accent-soft)",
          line: "var(--accent-line)",
        },
        surface: { DEFAULT: "var(--surface)", 2: "var(--surface-2)" },
        line: { DEFAULT: "var(--line)", strong: "var(--line-strong)" },
      },
      fontFamily: {
        display: ["Space Grotesk", "Inter", "system-ui", "sans-serif"],
        sans: ["Inter", "system-ui", "-apple-system", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "Consolas", "monospace"],
      },
      borderRadius: {
        token: "var(--radius-md)",
      },
      boxShadow: {
        soft: "var(--shadow-md)",
        lift: "var(--shadow-lg)",
      },
      transitionTimingFunction: {
        viper: "cubic-bezier(0.2, 0.7, 0.2, 1)",
      },
    },
  },
  plugins: [],
};
