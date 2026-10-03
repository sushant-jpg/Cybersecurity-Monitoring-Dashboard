import IORedis from "ioredis";
import { Queue } from "bullmq";
import { config } from "../config";

export const redis = new IORedis(config.REDIS_URL, {
  maxRetriesPerRequest: null,
  enableReadyCheck: false,
  lazyConnect: true
});

export const publisher = new IORedis(config.REDIS_URL, { lazyConnect: true });
export const eventQueue = new Queue("security-events", { connection: redis });

export async function ensureRedis(client: IORedis = redis): Promise<void> {
  if (client.status === "wait") await client.connect();
}
