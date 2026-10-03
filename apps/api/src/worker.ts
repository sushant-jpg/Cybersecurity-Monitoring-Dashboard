import { Worker } from "bullmq";
import { config } from "./config";
import { logger } from "./lib/logger";
import { processSecurityEvent, type EventJobData } from "./services/event-processor";
import { prisma } from "./lib/prisma";

const worker = new Worker<EventJobData>("security-events", async (job) => {
  logger.info({ jobId: job.id, requestId: job.data.requestId }, "Processing security event");
  return processSecurityEvent(job.data);
}, {
  connection: { url: config.REDIS_URL },
  concurrency: 10,
  limiter: { max: 100, duration: 1000 }
});

worker.on("completed", (job) => logger.info({ jobId: job.id }, "Security event processed"));
worker.on("failed", (job, error) => logger.error({ jobId: job?.id, err: error }, "Security event failed"));

const cleanup = async (): Promise<void> => {
  const organizations = await prisma.organization.findMany({ select: { id: true, eventRetentionDays: true, auditRetentionDays: true } });
  for (const org of organizations) {
    await prisma.securityEvent.deleteMany({
      where: { organizationId: org.id, timestamp: { lt: new Date(Date.now() - org.eventRetentionDays * 86_400_000) } }
    });
    await prisma.auditLog.deleteMany({
      where: { organizationId: org.id, timestamp: { lt: new Date(Date.now() - org.auditRetentionDays * 86_400_000) } }
    });
  }
};

const cleanupTimer = setInterval(() => void cleanup().catch((error) => logger.error({ err: error }, "Retention cleanup failed")), 86_400_000);
const heartbeatTimer = setInterval(() => void worker.client.then((client) => client.set("securewatch:worker:heartbeat", String(Date.now()), { EX: 60 })), 10_000);

async function shutdown(): Promise<void> {
  clearInterval(cleanupTimer);
  clearInterval(heartbeatTimer);
  await worker.close();
  await prisma.$disconnect();
  process.exit(0);
}

process.on("SIGTERM", () => void shutdown());
process.on("SIGINT", () => void shutdown());
