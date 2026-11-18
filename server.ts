import http from 'http';
import path from 'path';
import fs from 'fs';
import express from 'express';
import { createServer as createViteServer } from 'vite';
import { createServerApp } from './serverApp.ts';

async function startServer() {
  const app = createServerApp();
  
  // Port resolution:
  // - If --port <number> is explicitly passed as CLI arg, use it
  // - In Cloud Run / container environment, dev server and app-container run on port 3000
  const portArgIndex = process.argv.indexOf('--port');
  let PORT = 3000;
  if (portArgIndex !== -1 && process.argv[portArgIndex + 1]) {
    PORT = parseInt(process.argv[portArgIndex + 1], 10);
  } else if (process.env.PORT && process.env.PORT !== '8080') {
    PORT = parseInt(process.env.PORT, 10);
  } else {
    PORT = 3000;
  }

  const httpServer = http.createServer(app);

  const distPath = path.join(process.cwd(), 'dist');
  const distIndexHtml = path.join(distPath, 'index.html');
  const hasBuiltDist = fs.existsSync(distIndexHtml);

  // When dist/ is built (e.g. deployed build) and not explicitly running `npm run dev`,
  // serve the pre-built production bundle to avoid CPU-intensive on-the-fly bundling in Cloud Run.
  const isDev = process.env.npm_lifecycle_event === 'dev' || process.env.FORCE_DEV === 'true';

  if (isDev || (!hasBuiltDist && process.env.NODE_ENV !== 'production')) {
    const isHmrDisabled = process.env.DISABLE_HMR === 'true';
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: isHmrDisabled ? false : { server: httpServer }
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
    }
    app.get('*', (req, res) => {
      if (fs.existsSync(distIndexHtml)) {
        res.sendFile(distIndexHtml);
      } else {
        res.status(200).send(`<!doctype html><html lang="pt-BR"><head><meta charset="UTF-8"><title>REDE VIGIA</title></head><body><div id="root">Iniciando REDE VIGIA...</div></body></html>`);
      }
    });
  }

  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`REDE VIGIA backend running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
