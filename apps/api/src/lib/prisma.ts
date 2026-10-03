import { PrismaClient } from "@prisma/client";

declare global {
  var secureWatchPrisma: PrismaClient | undefined;
}

export const prisma = global.secureWatchPrisma ?? new PrismaClient({
  log: process.env.NODE_ENV === "development" ? ["warn", "error"] : ["error"]
});

if (process.env.NODE_ENV !== "production") global.secureWatchPrisma = prisma;
