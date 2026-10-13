import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `npm run dev` proxies the API to a running fsview (set FSVIEW_DEV_API).
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../internal/web/dist",
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    proxy: {
      "/api": { target: process.env.FSVIEW_DEV_API ?? "http://127.0.0.1:9200", changeOrigin: false },
    },
  },
});
