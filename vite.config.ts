// vite.config.ts
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  root: 'src/ui',
  base: './',
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src/ui'),
    }
  },
  build: {
    outDir: '../../dist',
    emptyOutDir: true,
    rollupOptions: {
      input: path.resolve(__dirname, 'src/ui/index.html'),
    }
  },
  server: {
    port: 3000,
    strictPort: true,
  }
});
