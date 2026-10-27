import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";
import { scoped, verifyAudit } from "@accountability/evidence/database";
import type { Database } from "@accountability/evidence/database";
import { PermissionRegistry } from "../src/registry.ts";
import { exactBinding } from "../src/index.ts";
import { digest } from "../src/contracts.ts";
import type { Context } from "../src/contracts.ts";
import type { ConsentOfferInput } from "../src/participant.ts";

const manager: Context = {
  tenantId: "fiction",
  projectId: "review",
  actor: { id: "manager", kind: "human", roles: ["owner"] },
  purpose: "education",
  requestId: "request",
  now: "2026-01-01T00:00:00Z",
};
const participant: Context = {
  ...manager,
  actor: { id: "person", kind: "human", roles: ["participant"] },
};
const resource = {
  ...exactBinding(
    { ...manager, kind: "image", id: "synthetic", revision: 1 },
    { fictional: true },
  ),
  requiredConsentSubjects: ["subject", "second-subject"],
};
// Ref must not carry context or actor fields.
resource.ref = {
  tenantId: manager.tenantId,
  projectId: manager.projectId,
  kind: "image",
  id: "synthetic",
  revision: 1,
};
const input: ConsentOfferInput = {
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
async function setup(t: test.TestContext) {
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
async function response(
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

test("exact participant review accepts atomically, replays once and shows current withdrawal", async (t) => {
  const { registry, db } = await setup(t);
  const review = await registry.reviewOffer(participant, "offer");
  assert.equal(review.responseOpen, true);
  assert.equal(review.consent, null);
  assert.equal(JSON.stringify(review).includes("second-subject"), false);
  const command = await response(registry);
  const accepted = await registry.respondToOffer(
    participant,
    command,
    "accept",
  );
  assert.equal(accepted.status, "accepted");
  assert.equal(accepted.ref.revision, 2);
  assert.deepEqual(
    await registry.respondToOffer(participant, command, "accept"),
    accepted,
  );
  const current = await registry.reviewOffer(participant, "offer");
  assert.equal(current.responseOpen, false);
  assert.equal(current.consent?.recordedBy, "person");
  assert.equal(current.consent?.subjectId, "subject");
  assert.equal(digest(current.consent), accepted.consent?.digest);
  await scoped(db, manager, async (tx) => {
    assert.equal((await tx.list("consent")).length, 1);
    assert.equal((await tx.list("consent-offer")).length, 1);
    const audits = await tx.audits();
    assert.equal(verifyAudit(audits), true);
    assert.equal(
      audits.filter((a) => a.type === "participant.offer.responded").length,
      1,
    );
    assert.equal(
      (await tx.claim("worker"))?.topic,
      "participant.offer.responded",
    );
  });
  await registry.withdraw(
    participant,
    "consent",
    current.consent!.ref.id,
    1,
    "withdraw",
  );
  const withdrawn = await registry.reviewOffer(participant, "offer");
  assert.equal(withdrawn.consent?.ref.revision, 2);
  assert.equal(withdrawn.consent?.withdrawnAt, participant.now);
  assert.equal(withdrawn.offer.consent?.ref.revision, 1); // Original receipt is immutable.
});

test("participants cannot impersonate another subject; managers and services cannot respond", async (t) => {
  const { registry } = await setup(t);
  const command = await response(registry);
  for (const context of [
    manager,
    {
      ...participant,
      actor: { ...participant.actor, kind: "service" as const },
    },
  ]) {
    await assert.rejects(registry.respondToOffer(context, command, "bad"), {
      code: "participant_required",
    });
  }
  const other = {
    ...participant,
    actor: { ...participant.actor, id: "other-person" },
  };
  await assert.rejects(registry.reviewOffer(other, "offer"), {
    code: "offer_unavailable",
  });
  await assert.rejects(registry.reviewOffer(other, "missing"), {
    code: "offer_unavailable",
  });
  await assert.rejects(registry.respondToOffer(other, command, "bad"), {
    code: "offer_unavailable",
  });
  await assert.rejects(
    registry.createOffer(participant, { ...input, id: "forged" }, "bad"),
    { code: "manager_required" },
  );
  await assert.rejects(
    registry.reviewOffer({ ...participant, projectId: "foreign" }, "offer"),
    { code: "scope_denied" },
  );
});

test("explicit acknowledgement, exact review and expiry reject without creating permission", async (t) => {
  const { registry, db } = await setup(t);
  const command = await response(registry);
  await assert.rejects(
    registry.respondToOffer(
      participant,
      { ...command, acknowledged: false },
      "a",
    ),
    { code: "acknowledgement_required" },
  );
  await assert.rejects(
    registry.respondToOffer(
      participant,
      { ...command, reviewDigest: "0".repeat(64) },
      "b",
    ),
    { code: "review_changed" },
  );
  await assert.rejects(
    registry.respondToOffer(
      participant,
      { ...command, expectedRevision: 2 },
      "c",
    ),
    { code: "review_changed" },
  );
  const expired = { ...participant, now: input.responseExpiresAt };
  assert.equal(
    (await registry.reviewOffer(expired, "offer")).responseOpen,
    false,
  );
  await assert.rejects(registry.respondToOffer(expired, command, "d"), {
    code: "offer_expired",
  });
  await scoped(db, manager, async (tx) =>
    assert.equal((await tx.list("consent")).length, 0),
  );
});

test("decline and cancellation are terminal proposals, never permission or withdrawal", async (t) => {
  const { registry, db } = await setup(t);
  const command = await response(registry, "decline");
  const declined = await registry.respondToOffer(
    participant,
    command,
    "decline",
  );
  assert.equal(declined.status, "declined");
  assert.equal(declined.consent, null);
  await assert.rejects(
    registry.cancelOffer(manager, "offer", 2, "cancel-declined"),
    { code: "offer_closed" },
  );
  await registry.createOffer(manager, { ...input, id: "cancel-me" }, "second");
  const reviewed = await registry.reviewOffer(participant, "cancel-me");
  await registry.cancelOffer(manager, "cancel-me", 1, "cancel");
  await assert.rejects(
    registry.respondToOffer(
      participant,
      {
        ...command,
        offerId: "cancel-me",
        response: "accept",
        acknowledged: true,
        reviewDigest: reviewed.reviewDigest,
      },
      "stale",
    ),
    { code: "review_changed" },
  );
  await scoped(db, manager, async (tx) =>
    assert.equal((await tx.list("consent")).length, 0),
  );
});
