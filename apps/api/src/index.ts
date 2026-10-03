import http from "node:http";
import { Server } from "socket.io";
import IORedis from "ioredis";
import { createApp } from "./app";
import { config } from "./config";
import { logger } from "./lib/logger";
import { verifyAccessToken } from "./lib/security";
import { prisma } from "./lib/prisma";
import { eventQueue, publisher, redis } from "./lib/redis";

const app = createApp();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: config.FRONTEND_URL, credentials: true } });

io.use((socket, next) => {
  const token = socket.handshake.auth.token as string | undefined;
  if (!token) return next(new Error("Authentication required"));
  try {
    const claims = verifyAccessToken(token);
    socket.data.organizationId = claims.organizationId;
    socket.data.userId = claims.sub;
    next();
  } catch {
    next(new Error("Invalid or expired token"));
  }
});

io.on("connection", (socket) => {
  void socket.join(`organization:${String(socket.data.organizationId)}`);
  socket.emit("connection.ready", { connectedAt: new Date().toISOString() });
});

const subscriber = new IORedis(config.REDIS_URL, { lazyConnect: true });
subscriber.connect()
  .then(() => subscriber.subscribe("securewatch:realtime"))
  .catch((error) => logger.warn({ err: error }, "Realtime subscriber unavailable"));
subscriber.on("message", (_channel, raw) => {
  try {
    const message = JSON.parse(raw) as { organizationId: string; type: string; payload: unknown };
    io.to(`organization:${message.organizationId}`).emit(message.type, message.payload);
  } catch (error) {
    logger.warn({ err: error }, "Invalid realtime message ignored");
  }
});

server.listen(config.PORT, () => logger.info({ port: config.PORT }, "SecureWatch API listening"));

async function shutdown(): Promise<void> {
  logger.info("Shutting down API");
  io.close();
  server.close();
  await Promise.allSettled([subscriber.quit(), eventQueue.close(), redis.quit(), publisher.quit(), prisma.$disconnect()]);
}

process.on("SIGTERM", () => void shutdown());
process.on("SIGINT", () => void shutdown());
