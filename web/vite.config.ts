import { writeFileSync } from "node:fs";
import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Go's embed needs dist/ to hold a file even before the UI is built, so the
// committed placeholder is restored after Vite empties the directory.
const keepDist: Plugin = {
  name: "deaconguard-keep-dist",
  closeBundle: () => writeFileSync("dist/.gitkeep", ""),
};

// `npm run dev` serves the UI on :5173 and forwards /api to `deaconguard serve`.
export default defineConfig({
  plugins: [react(), tailwindcss(), keepDist],
  build: { outDir: "dist", emptyOutDir: true },
  server: {
    proxy: {
      "/api": {
        target: "http://127.0.0.1:7480",
        changeOrigin: true,
        // The API rejects requests whose Origin differs from its own address.
        configure: (proxy) => proxy.on("proxyReq", (request) => request.removeHeader("origin")),
      },
    },
  },
});
