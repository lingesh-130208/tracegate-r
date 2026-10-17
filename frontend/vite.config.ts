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
