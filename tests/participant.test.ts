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
  await registry.grantRights(
    manager,
    {
      ...input.terms,
      id: "rights",
      holderId: "fictional-holder",
      attribution: null,
      noDerivatives: false,
    },
    "rights",
  );
  await registry.recordConsent(
    manager,
    { ...input.terms, id: "second-consent", subjectId: "second-subject" },
    "second-consent",
  );
  const evaluation = () =>
    registry.evaluate(
      manager,
      resource.ref,
      { action: "reproduce", audience: "private", attribution: null },
      {
        rights: ["rights"],
        consents: [accepted.consent!.ref.id, "second-consent"],
      },
    );
  assert.equal((await evaluation()).allowed, true);
  const current = await registry.reviewOffer(participant, "offer");
  assert.equal(current.responseOpen, false);
  assert.equal(current.consent?.recordedBy, "person");
  assert.equal(current.consent?.subjectId, "subject");
  assert.equal(digest(current.consent), accepted.consent?.digest);
  await scoped(db, manager, async (tx) => {
    assert.equal((await tx.list("consent")).length, 2);
    assert.equal((await tx.list("consent-offer")).length, 1);
    const original = await tx.get(
      "consent-offer",
      digest({ kind: "consent-offer", id: "offer" }),
      1,
    );
    assert.equal(digest(original!.value), digest(review.offer));
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
  assert.equal((await evaluation()).allowed, false);
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

test("replay binds exact command purpose and current participant mapping, including after withdrawal", async (t) => {
  const { registry, db, policy } = await setup(t);
  const command = await response(registry);
  const accepted = await registry.respondToOffer(
    participant,
    command,
    "accept",
  );
  await assert.rejects(
    registry.respondToOffer(
      participant,
      { ...command, response: "decline" },
      "accept",
    ),
    { code: "idempotency_conflict" },
  );
  await assert.rejects(
    registry.respondToOffer(
      { ...participant, purpose: "changed-purpose" },
      command,
      "accept",
    ),
    { code: "idempotency_conflict" },
  );
  const revoked = new PermissionRegistry(db, {
    ...policy,
    participantActors: { subject: "replacement" },
  });
  await assert.rejects(revoked.respondToOffer(participant, command, "accept"), {
    code: "offer_unavailable",
  });
  await registry.withdraw(
    participant,
    "consent",
    accepted.consent!.ref.id,
    1,
    "withdraw",
  );
  assert.deepEqual(
    await registry.respondToOffer(participant, command, "accept"),
    accepted,
  );
  assert.equal(
    (await registry.reviewOffer(participant, "offer")).consent?.withdrawnAt,
    participant.now,
  );
  await assert.rejects(
    revoked.withdraw(
      participant,
      "consent",
      accepted.consent!.ref.id,
      1,
      "withdraw",
    ),
    { code: "manager_required" },
  );
  await assert.rejects(
    registry.respondToOffer(participant, command, "new-accept"),
    { code: "review_changed" },
  );
});

test("lost commit acknowledgement reconciles from durable state without duplicating consent or events", async (t) => {
  const { registry, db, policy } = await setup(t);
  const command = await response(registry);
  let lose = true;
  const flaky: Database = {
    transaction: async (fn) => {
      const result = await db.transaction(fn);
      if (lose) {
        lose = false;
        throw new Error("lost acknowledgement after commit");
      }
      return result;
    },
    close: async () => {},
  };
  const gateway = new PermissionRegistry(flaky, policy);
  await assert.rejects(
    gateway.respondToOffer(participant, command, "uncertain"),
    /lost acknowledgement/,
  );
  const reopened = new PermissionRegistry(db, policy);
  const reconciled = await reopened.respondToOffer(
    participant,
    command,
    "uncertain",
  );
  assert.equal(reconciled.status, "accepted");
  await scoped(db, manager, async (tx) => {
    assert.equal((await tx.list("consent")).length, 1);
    assert.equal(
      (await tx.audits()).filter(
        (a) => a.type === "participant.offer.responded",
      ).length,
      1,
    );
    const event = await tx.claim("worker");
    assert.equal(event?.topic, "participant.offer.responded");
    await tx.acknowledge(event!);
    assert.equal(await tx.claim("worker"), null);
  });
});

test("failure after consent insertion rolls back consent, response, audit and impact together", async (t) => {
  const { registry, db, policy } = await setup(t);
  const command = await response(registry);
  let inserted = false;
  const failing: Database = {
    transaction: (fn) =>
      db.transaction((q) =>
        fn({
          query: async <T>(sql: string, params?: unknown[]) => {
            const result = await q.query<T>(sql, params);
            if (
              sql.includes("INSERT INTO public.evidence_record") &&
              params?.includes("consent")
            ) {
              inserted = true;
              throw new Error("injected transactional failure");
            }
            return result;
          },
        }),
      ),
    close: async () => {},
  };
  await assert.rejects(
    new PermissionRegistry(failing, policy).respondToOffer(
      participant,
      command,
      "rollback",
    ),
    /injected transactional failure/,
  );
  assert.equal(inserted, true);
  assert.equal(
    (await registry.reviewOffer(participant, "offer")).offer.status,
    "offered",
  );
  await scoped(db, manager, async (tx) => {
    assert.equal((await tx.list("consent")).length, 0);
    assert.equal(
      (await tx.audits()).filter(
        (a) => a.type === "participant.offer.responded",
      ).length,
      0,
    );
    assert.equal(await tx.claim("worker"), null);
  });
  assert.equal(
    (await registry.respondToOffer(participant, command, "rollback")).status,
    "accepted",
  );
});

test("offers reject extra data, foreign/unregistered bindings, unbound subjects and invalid terms", async (t) => {
  const { registry } = await setup(t);
  const invalid = [
    { ...input, id: "extra", internalNotes: "must not be echoed" },
    { ...input, id: "resource-extra", terms: { ...input.terms, resource } },
    { ...input, id: "long", disclosure: "x".repeat(16001) },
    { ...input, id: "late", responseExpiresAt: "2027-01-01T00:00:00Z" },
    { ...input, id: "wildcard", terms: { ...input.terms, purposes: ["*"] } },
  ];
  for (const value of invalid)
    await assert.rejects(registry.createOffer(manager, value, value.id));
  await assert.rejects(
    registry.createOffer(
      manager,
      { ...input, id: "unbound", subjectId: "unbound" },
      "unbound",
    ),
    { code: "participant_unbound" },
  );
  await assert.rejects(
    registry.createOffer(
      manager,
      {
        ...input,
        id: "foreign",
        terms: {
          ...input.terms,
          resource: {
            ...input.terms.resource,
            ref: { ...resource.ref, projectId: "foreign" },
          },
        },
      },
      "foreign",
    ),
    { code: "scope_denied" },
  );
  await assert.rejects(
    registry.createOffer(
      manager,
      {
        ...input,
        id: "wrong",
        terms: {
          ...input.terms,
          resource: { ...input.terms.resource, digest: "0".repeat(64) },
        },
      },
      "wrong",
    ),
    { code: "resource_changed" },
  );
});

test("context, offer and response input are captured before asynchronous storage", async (t) => {
  const { registry } = await setup(t);
  const proposed = structuredClone({ ...input, id: "captured" });
  const creating = registry.createOffer(manager, proposed, "captured");
  proposed.disclosure = "tampered";
  assert.equal((await creating).disclosure, input.disclosure);
  const context = structuredClone(participant);
  const command = await response(registry);
  const responding = registry.respondToOffer(
    context,
    command,
    "response-captured",
  );
  command.response = "decline";
  (context.actor as { id: string }).id = "tampered";
  const result = await responding;
  assert.equal(result.status, "accepted");
  assert.equal(result.resolvedBy, "person");
});

test("concurrent distinct responses serialize to one resolved proposal and one impact event", async (t) => {
  const { registry, db } = await setup(t);
  const command = await response(registry);
  const results = await Promise.allSettled([
    registry.respondToOffer(participant, command, "race-accept"),
    registry.respondToOffer(
      participant,
      { ...command, response: "decline", acknowledged: false },
      "race-decline",
    ),
  ]);
  assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
  assert.equal(results.filter((r) => r.status === "rejected").length, 1);
  const current = await registry.reviewOffer(participant, "offer");
  assert.notEqual(current.offer.status, "offered");
  await scoped(db, manager, async (tx) => {
    assert.equal(
      (await tx.list("consent")).length,
      current.offer.status === "accepted" ? 1 : 0,
    );
    assert.equal(
      (await tx.audits()).filter(
        (a) => a.type === "participant.offer.responded",
      ).length,
      1,
    );
  });
  // An acknowledged manager command is still reconcilable after the proposal's deadline.
  assert.deepEqual(
    await registry.createOffer(
      { ...manager, now: input.responseExpiresAt },
      input,
      "create-offer",
    ),
    {
      ...current.offer,
      status: "offered",
      ref: { ...current.offer.ref, revision: 1 },
      resolvedAt: null,
      resolvedBy: null,
      consent: null,
    },
  );
});
