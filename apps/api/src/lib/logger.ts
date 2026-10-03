import pino from "pino";

export const logger = pino({
  name: "securewatch-api",
  level: process.env.LOG_LEVEL ?? "info",
  redact: {
    paths: [
      "password", "passwordHash", "token", "refreshToken", "accessToken", "apiKey",
      "req.headers.authorization", "req.headers.cookie", "req.headers.x-api-key"
    ],
    censor: "[REDACTED]"
  }
});
