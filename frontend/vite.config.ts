import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const frontendRoot = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  root: frontendRoot,
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": resolve(frontendRoot, "src") },
  },
  server: {
    host: "127.0.0.1",
    // Keep the origin stable because the local backend allowlist uses this exact value.
    port: 5173,
    strictPort: true,
    // Browser requests are same-origin to Vite, then forwarded to FastAPI.
    // Do not rewrite the browser Origin header; the backend explicitly allowlists
    // this local development origin when started with the documented PowerShell env.
    proxy: {
      "/health": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
      },
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
      },
    },
    fs: { allow: [resolve(frontendRoot, ".."), frontendRoot] },
  },
  build: {
    outDir: resolve(frontendRoot, "dist"),
    emptyOutDir: true,
    assetsDir: "assets",
  },
  test: {
    environment: "jsdom",
    setupFiles: [resolve(frontendRoot, "src/test/setup.ts")],
    restoreMocks: true,
    clearMocks: true,
  },
});
