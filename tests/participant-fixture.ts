import test from "node:test";
import { readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";
import type { Database } from "@accountability/evidence/database";
import { PermissionRegistry } from "../src/registry.ts";
import { exactBinding } from "../src/index.ts";
import type { Context } from "../src/contracts.ts";
import type { ConsentOfferInput } from "../src/participant.ts";

export const manager: Context = {
  tenantId: "fiction",
  projectId: "review",
  actor: { id: "manager", kind: "human", roles: ["owner"] },
  purpose: "education",
  requestId: "request",
  now: "2026-01-01T00:00:00Z",
};
export const participant: Context = {
  ...manager,
  actor: { id: "person", kind: "human", roles: ["participant"] },
};
export const resource = {
  ...exactBinding(
    {
      tenantId: manager.tenantId,
      projectId: manager.projectId,
      kind: "image",
      id: "synthetic",
      revision: 1,
    },
    { fictional: true },
  ),
  requiredConsentSubjects: ["subject", "second-subject"],
};
export const input: ConsentOfferInput = {
  id: "offer",
  subjectId: "subject",
  disclosure:
    "The synthetic image may be reproduced for private educational review. Participation is optional.",
  responseExpiresAt: "2026-01-10T00:00:00Z",
  terms: {
    resource: { ref: resource.ref, digest: resource.digest },
    actions: ["reproduce"],
    purposes: ["education"],
    audiences: ["private"],
    validFrom: manager.now,
    expiresAt: "2026-02-01T00:00:00Z",
    evidence: {
      ...resource.ref,
      kind: "disclosure-document",
      id: "terms-evidence",
    },
  },
};
export async function setup(t: test.TestContext) {
  const pg = new PGlite();
  await pg.exec(
    await readFile(
      new URL(
        "../migrations/001_foundation.sql",
        import.meta.resolve("@accountability/evidence/database"),
      ),
      "utf8",
    ),
  );
  await pg.exec(
    "CREATE ROLE participant_login LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION; GRANT evidence_runtime TO participant_login; SET SESSION AUTHORIZATION participant_login",
  );
  const db: Database = {
    transaction: (fn) =>
      pg.transaction((q) =>
        fn({
          query: async <T>(sql: string, params?: unknown[]) => ({
            rows: (await q.query(sql, params)).rows as T[],
          }),
        }),
      ),
    close: () => pg.close(),
  };
  t.after(() => pg.close());
  const policy = {
    tenantId: manager.tenantId,
    projectId: manager.projectId,
    managerIds: ["manager"],
    participantActors: { subject: "person", "second-subject": "other-person" },
  };
  const registry = new PermissionRegistry(db, policy);
  await registry.registerResource(manager, resource, 0);
  await registry.createOffer(manager, input, "create-offer");
  return { db, registry, policy };
}
export async function response(
  registry: PermissionRegistry,
  value: "accept" | "decline" = "accept",
) {
  const review = await registry.reviewOffer(participant, "offer");
  return {
    offerId: "offer",
    expectedRevision: review.offer.ref.revision,
    reviewDigest: review.reviewDigest,
    response: value,
    acknowledged: value === "accept",
  };
}
