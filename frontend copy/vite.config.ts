import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import fs from "fs";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: "0.0.0.0",
    https: {
      key: fs.readFileSync('../omniwatch.local-key.pem'),
      cert: fs.readFileSync('../omniwatch.local.pem'),
    },
    proxy: {
      "/api": { target: "http://localhost:8080", changeOrigin: true },
      "/ws":  { target: "ws://localhost:8080", ws: true, changeOrigin: true },
    },
  },
});
