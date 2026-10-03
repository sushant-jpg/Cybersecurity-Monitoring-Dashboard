import { afterAll, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { createApp } from "./app";
import { prisma } from "./lib/prisma";
import { ensureRedis, redis } from "./lib/redis";
import { sha256 } from "./lib/security";

const runIntegrationTests = Boolean(process.env.TEST_DATABASE_URL);
const suffix = `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
const organizationSlug = `phase1-a-${suffix}`;
const secondOrganizationSlug = `phase1-b-${suffix}`;
const password = "PhaseOne!Integration2026";
const app = createApp();

describe.skipIf(!runIntegrationTests)("Phase 1 HTTP integration", () => {
  beforeAll(async () => {
    if (!process.env.TEST_DATABASE_URL) throw new Error("TEST_DATABASE_URL is required");
    process.env.DATABASE_URL = process.env.TEST_DATABASE_URL;
    await prisma.$connect();
    await ensureRedis();
    await redis.ping();
  }, 30_000);

  afterAll(async () => {
    await prisma.organization.deleteMany({
      where: { slug: { in: [organizationSlug, secondOrganizationSlug] } }
    });
    await Promise.all([prisma.$disconnect(), redis.quit()]);
  }, 30_000);

  it("covers registration, sessions, tenant isolation, RBAC, API keys, audit, and readiness", async () => {
    const live = await request(app).get("/health/live").expect(200);
    expect(live.body.data.status).toBe("alive");
    expect(live.headers["x-request-id"]).toBeTruthy();

    const ready = await request(app).get("/health/ready").expect(200);
    expect(ready.body.data.dependencies).toEqual({ postgresql: "healthy", redis: "healthy" });

    const ownerEmail = `owner-${suffix}@example.test`;
    const registration = await request(app).post("/api/v1/auth/register").send({
      organizationName: "Phase One Test Organization",
      organizationSlug,
      name: "Test Owner",
      email: ownerEmail,
      password
    }).expect(201);
    expect(registration.body.data.user.role).toBe("SUPER_ADMIN");
    expect(registration.body.data.demoVerificationToken).toBeTruthy();
    expect(await prisma.auditLog.count({ where: { organizationId: (await prisma.organization.findUniqueOrThrow({ where: { slug: organizationSlug } })).id, action: "ORGANIZATION_REGISTERED" } })).toBe(1);

    await request(app).post("/api/v1/auth/verify-email").send({
      token: registration.body.data.demoVerificationToken
    }).expect(200);

    const owner = request.agent(app);
    const login = await owner.post("/api/v1/auth/login").send({
      organizationSlug,
      email: ownerEmail,
      password
    }).expect(200);
    const oldRefreshCookie = login.headers["set-cookie"]
      .find((cookie: string) => cookie.startsWith("refresh_token="))
      .split(";")[0];

    expect((await owner.get("/api/v1/auth/sessions").expect(200)).body.data).toHaveLength(1);
    const refreshed = await owner.post("/api/v1/auth/refresh").send({}).expect(200);
    expect(refreshed.body.data.accessToken).toBeTruthy();
    expect((await owner.get("/api/v1/auth/sessions").expect(200)).body.data).toHaveLength(1);

    await request(app).post("/api/v1/auth/refresh")
      .set("cookie", oldRefreshCookie)
      .send({})
      .expect(401);
    expect((await owner.get("/api/v1/auth/sessions").expect(200)).body.data).toHaveLength(0);

    const reauthenticated = await owner.post("/api/v1/auth/login").send({
      organizationSlug,
      email: ownerEmail,
      password
    }).expect(200);
    await owner.post("/api/v1/auth/logout")
      .set("authorization", `Bearer ${reauthenticated.body.data.accessToken}`)
      .send({})
      .expect(200);
    expect((await owner.get("/api/v1/auth/sessions").expect(200)).body.data).toHaveLength(0);

    const authenticatedOwner = request.agent(app);
    const secondLogin = await authenticatedOwner.post("/api/v1/auth/login").send({
      organizationSlug,
      email: ownerEmail,
      password
    }).expect(200);
    const ownerToken = secondLogin.body.data.accessToken as string;

    const createdApplication = await authenticatedOwner.post("/api/v1/applications")
      .set("authorization", `Bearer ${ownerToken}`)
      .send({ name: "Phase One API", environment: "test", type: "REST API" })
      .expect(201);
    const applicationId = createdApplication.body.data.id as string;

    const createdKey = await authenticatedOwner.post(`/api/v1/applications/${applicationId}/keys`)
      .set("authorization", `Bearer ${ownerToken}`)
      .send({ name: "Integration key" })
      .expect(201);
    const originalKey = createdKey.body.data.apiKey as string;
    const originalKeyRecord = await prisma.apiKey.findUniqueOrThrow({
      where: { id: createdKey.body.data.id }
    });
    expect(originalKeyRecord.keyHash).toBe(sha256(originalKey));
    expect(originalKeyRecord.keyHash).not.toBe(originalKey);

    const newUser = await authenticatedOwner.post("/api/v1/users")
      .set("authorization", `Bearer ${ownerToken}`)
      .send({
        name: "Test Viewer",
        email: `viewer-${suffix}@example.test`,
        password: "ViewerPass!Integration2026",
        role: "VIEWER"
      })
      .expect(201);
    expect(newUser.body.data.role).toBe("VIEWER");

    const viewer = request.agent(app);
    const viewerLogin = await viewer.post("/api/v1/auth/login").send({
      organizationSlug,
      email: `viewer-${suffix}@example.test`,
      password: "ViewerPass!Integration2026"
    }).expect(200);
    await viewer.post("/api/v1/applications")
      .set("authorization", `Bearer ${viewerLogin.body.data.accessToken}`)
      .send({ name: "Forbidden Application", environment: "test", type: "REST API" })
      .expect(403);

    const secondRegistration = await request(app).post("/api/v1/auth/register").send({
      organizationName: "Second Phase One Organization",
      organizationSlug: secondOrganizationSlug,
      name: "Second Owner",
      email: `owner-${suffix}@other.example.test`,
      password
    }).expect(201);
    await request(app).post("/api/v1/auth/verify-email").send({
      token: secondRegistration.body.data.demoVerificationToken
    }).expect(200);

    const secondTenant = request.agent(app);
    const secondTenantLogin = await secondTenant.post("/api/v1/auth/login").send({
      organizationSlug: secondOrganizationSlug,
      email: `owner-${suffix}@other.example.test`,
      password
    }).expect(200);
    const secondTenantToken = secondTenantLogin.body.data.accessToken as string;
    expect((await secondTenant.get("/api/v1/applications")
      .set("authorization", `Bearer ${secondTenantToken}`)
      .expect(200)).body.data).toHaveLength(0);
    await secondTenant.post(`/api/v1/applications/${applicationId}/keys/${createdKey.body.data.id}/rotate`)
      .set("authorization", `Bearer ${secondTenantToken}`)
      .send({})
      .expect(404);
    await secondTenant.delete(`/api/v1/applications/${applicationId}/keys/${createdKey.body.data.id}`)
      .set("authorization", `Bearer ${secondTenantToken}`)
      .expect(404);

    const rotatedKey = await authenticatedOwner.post(`/api/v1/applications/${applicationId}/keys/${createdKey.body.data.id}/rotate`)
      .set("authorization", `Bearer ${ownerToken}`)
      .send({})
      .expect(201);
    const rotatedKeyRecord = await prisma.apiKey.findUniqueOrThrow({
      where: { id: rotatedKey.body.data.id }
    });
    expect(rotatedKeyRecord.keyHash).toBe(sha256(rotatedKey.body.data.apiKey));
    expect((await prisma.apiKey.findUniqueOrThrow({ where: { id: createdKey.body.data.id } })).revokedAt).not.toBeNull();

    await authenticatedOwner.delete(`/api/v1/applications/${applicationId}/keys/${rotatedKey.body.data.id}`)
      .set("authorization", `Bearer ${ownerToken}`)
      .expect(200);
    expect((await prisma.apiKey.findUniqueOrThrow({ where: { id: rotatedKey.body.data.id } })).revokedAt).not.toBeNull();
    expect(await prisma.auditLog.count({
      where: { action: { in: ["API_KEY_CREATED", "API_KEY_ROTATED", "API_KEY_REVOKED"] } }
    })).toBeGreaterThanOrEqual(3);
  }, 60_000);
});
