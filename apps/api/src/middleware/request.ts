import crypto from "node:crypto";
import type { NextFunction, Request, Response } from "express";

export function requestContext(req: Request, res: Response, next: NextFunction): void {
  const supplied = req.header("x-request-id");
  req.requestId = supplied && /^[a-zA-Z0-9._:-]{8,128}$/.test(supplied) ? supplied : crypto.randomUUID();
  res.setHeader("x-request-id", req.requestId);
  next();
}
