import type { UserRole } from "@prisma/client";

declare global {
  namespace Express {
    interface Request {
      requestId: string;
      auth?: { userId: string; organizationId: string; role: UserRole };
      applicationAuth?: { applicationId: string; organizationId: string; apiKeyId: string };
    }
  }
}

export {};
