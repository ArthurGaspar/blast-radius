import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

// Default mode runs the engine in the browser (GitHub Pages). `--mode api` talks to the ASP.NET Core API (.env.api).
export default defineConfig({
  base: "./",
  plugins: [react()],
  resolve: { alias: { "@shared": fileURLToPath(new URL("../shared", import.meta.url)) } },
  server: { fs: { allow: [".."] } },
});
