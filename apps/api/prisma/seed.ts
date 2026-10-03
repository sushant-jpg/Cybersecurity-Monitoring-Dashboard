import argon2 from "argon2";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function main(): Promise<void> {
  if (process.env.NODE_ENV === "production") {
    throw new Error("The demo seed cannot run in production");
  }
  const organization = await prisma.organization.upsert({
    where: { slug: "acme-security" }, update: {}, create: { name: "Acme Security Labs", slug: "acme-security" }
  });
  const passwordHash = await argon2.hash("SecureWatch!2026", { type: argon2.argon2id });
  const demoUsers = [
    ["admin@securewatch.local", "Aarav Sharma", "SUPER_ADMIN"],
    ["analyst@securewatch.local", "Maya Thapa", "SECURITY_ANALYST"],
    ["it@securewatch.local", "Daniel Kim", "IT_ADMIN"],
    ["viewer@securewatch.local", "Sofia Patel", "VIEWER"]
  ] as const;
  for (const [email, name, role] of demoUsers) {
    await prisma.user.upsert({
      where: { organizationId_email: { organizationId: organization.id, email } },
      update: {}, create: { organizationId: organization.id, email, name, role, passwordHash, emailVerifiedAt: new Date() }
    });
  }
  let application = await prisma.application.findFirst({ where: { organizationId: organization.id, name: "E-Commerce Production API" } });
  if (!application) application = await prisma.application.create({ data: { organizationId: organization.id, name: "E-Commerce Production API", environment: "Production", type: "Node.js API" } });
  console.log("Seed complete");
  console.log("Organization: acme-security");
  console.log("Demo password: SecureWatch!2026");
  console.log(`Application ID: ${application.id}`);
}

main().finally(() => prisma.$disconnect());
