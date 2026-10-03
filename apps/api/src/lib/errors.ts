import type { NextFunction, Request, Response } from "express";
import { ZodError } from "zod";
import { logger } from "./logger";

export class HttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
    public readonly details?: unknown
  ) {
    super(message);
  }
}

export function isUniqueConstraintError(error: unknown): boolean {
  return Boolean(
    error &&
    typeof error === "object" &&
    "code" in error &&
    error.code === "P2002"
  );
}

export const asyncHandler = (
  handler: (req: Request, res: Response, next: NextFunction) => Promise<unknown>
) => (req: Request, res: Response, next: NextFunction): void => {
  Promise.resolve(handler(req, res, next)).catch(next);
};

export function notFound(req: Request, _res: Response, next: NextFunction): void {
  next(new HttpError(404, "ROUTE_NOT_FOUND", `Route ${req.method} ${req.path} was not found`));
}

export function errorHandler(error: unknown, req: Request, res: Response, _next: NextFunction): void {
  const requestId = req.requestId ?? "unknown";
  if (
    error &&
    typeof error === "object" &&
    "type" in error &&
    error.type === "entity.parse.failed"
  ) {
    res.status(400).json({
      success: false,
      error: { code: "INVALID_JSON", message: "Request body must contain valid JSON", requestId }
    });
    return;
  }
  if (
    error &&
    typeof error === "object" &&
    "type" in error &&
    error.type === "entity.too.large"
  ) {
    res.status(413).json({
      success: false,
      error: { code: "PAYLOAD_TOO_LARGE", message: "Request body exceeds the permitted size", requestId }
    });
    return;
  }
  if (error instanceof ZodError) {
    res.status(422).json({
      success: false,
      error: { code: "VALIDATION_ERROR", message: "Request validation failed", requestId, details: error.flatten() }
    });
    return;
  }
  if (error instanceof HttpError) {
    res.status(error.status).json({
      success: false,
      error: { code: error.code, message: error.message, requestId, ...(error.details ? { details: error.details } : {}) }
    });
    return;
  }
  logger.error({ err: error, requestId }, "Unhandled request error");
  res.status(500).json({
    success: false,
    error: { code: "INTERNAL_ERROR", message: "An unexpected error occurred", requestId }
  });
}
