import "dotenv/config";
import { z } from "zod";

const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().positive().default(4000),
  DATABASE_URL: z.string().default("postgresql://securewatch:securewatch@localhost:5432/securewatch?schema=public"),
  REDIS_URL: z.string().default("redis://localhost:6379"),
  JWT_ACCESS_SECRET: z.string().min(32).default("development-access-secret-change-me-now"),
  JWT_REFRESH_SECRET: z.string().min(32).default("development-refresh-secret-change-me-now"),
  FRONTEND_URL: z.string().url().default("http://localhost:3000"),
  API_URL: z.string().url().default("http://localhost:4000"),
  THREAT_PROVIDER: z.enum(["demo", "virustotal", "abuseipdb"]).default("demo"),
  VIRUSTOTAL_API_KEY: z.string().optional(),
  ABUSEIPDB_API_KEY: z.string().optional(),
  EVENT_RETENTION_DAYS: z.coerce.number().int().positive().default(90),
  AUDIT_RETENTION_DAYS: z.coerce.number().int().positive().default(365),
  COOKIE_SECURE: z.enum(["true", "false"]).optional().transform((value) => value === undefined ? process.env.NODE_ENV === "production" : value === "true"),
  DEMO_MODE: z.enum(["true", "false"]).optional().transform((value) => value === undefined ? process.env.NODE_ENV !== "production" : value === "true")
});

export const config = schema.parse(process.env);

if (config.NODE_ENV === "production") {
  if (
    !process.env.JWT_ACCESS_SECRET ||
    !process.env.JWT_REFRESH_SECRET ||
    /^(development-|replace-with|change-me)/i.test(config.JWT_ACCESS_SECRET) ||
    /^(development-|replace-with|change-me)/i.test(config.JWT_REFRESH_SECRET) ||
    config.JWT_ACCESS_SECRET === config.JWT_REFRESH_SECRET
  ) {
    throw new Error("Production requires distinct, explicitly configured JWT secrets");
  }
  if (!config.COOKIE_SECURE) {
    throw new Error("Production authentication cookies must use Secure");
  }
  if (config.DEMO_MODE) {
    throw new Error("DEMO_MODE must be disabled in production");
  }
}
