import { describe, expect, it } from "vitest";
import request from "supertest";
import { createApp } from "./app";

describe("HTTP API", () => {
  const app = createApp();

  it("reports liveness without depending on external services", async () => {
    const response = await request(app).get("/health/live").expect(200);
    expect(response.body).toEqual(expect.objectContaining({ success: true, data: expect.objectContaining({ status: "alive" }) }));
    expect(response.headers["x-request-id"]).toBeTruthy();
    expect(response.headers["x-powered-by"]).toBeUndefined();
  });

  it("enforces authentication on tenant resources", async () => {
    const response = await request(app).get("/api/v1/users").expect(401);
    expect(response.body.error.code).toBe("AUTH_REQUIRED");
    expect(response.body.error.requestId).toBeTruthy();
  });

  it("returns standardized errors for unknown routes", async () => {
    const response = await request(app).get("/missing").expect(404);
    expect(response.body).toEqual(expect.objectContaining({ success: false, error: expect.objectContaining({ code: "ROUTE_NOT_FOUND" }) }));
  });

  it("keeps later-phase APIs unavailable until they are implemented", async () => {
    const response = await request(app).get("/api/v1/analytics/overview").expect(404);
    expect(response.body.error.code).toBe("ROUTE_NOT_FOUND");
  });

  it("uses the standard error envelope for malformed JSON", async () => {
    const response = await request(app)
      .post("/api/v1/auth/login")
      .set("content-type", "application/json")
      .send('{"email":')
      .expect(400);
    expect(response.body.error).toEqual(expect.objectContaining({
      code: "INVALID_JSON",
      requestId: expect.any(String)
    }));
  });

  it("returns standardized Zod validation failures", async () => {
    const response = await request(app)
      .post("/api/v1/auth/register")
      .send({ organizationName: "x", organizationSlug: "X", name: "x", email: "bad", password: "short" })
      .expect(422);
    expect(response.body.error).toEqual(expect.objectContaining({
      code: "VALIDATION_ERROR",
      requestId: expect.any(String)
    }));
  });

  it("keeps a validated request ID consistent in the response", async () => {
    const requestId = "phase1-test-request-0001";
    const response = await request(app)
      .get("/health/live")
      .set("x-request-id", requestId)
      .expect(200);
    expect(response.headers["x-request-id"]).toBe(requestId);
  });
});
