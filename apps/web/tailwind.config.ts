import type { Config } from "tailwindcss";

export default {
  darkMode: ["class"],
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        background: "hsl(var(--background))", foreground: "hsl(var(--foreground))",
        card: "hsl(var(--card))", border: "hsl(var(--border))", muted: "hsl(var(--muted))",
        primary: "hsl(var(--primary))", danger: "hsl(var(--danger))"
      },
      boxShadow: { panel: "0 18px 50px rgba(0,0,0,.18)" }
    }
  },
  plugins: []
} satisfies Config;
