import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Simple API to get IP and simulate tunneling check
  app.get("/api/network-check", (req, res) => {
    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
    // In a real app, you'd use a GeoIP service here. 
    // We'll return the IP and a simulated status.
    res.json({
      ip,
      status: "SECURE",
      tunnelingDetected: false,
      timestamp: new Date().toISOString()
    });
  });

  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
