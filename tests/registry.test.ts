import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";
import type { Database } from "@accountability/evidence/database";
import { scoped, verifyAudit } from "@accountability/evidence/database";
import { PermissionRegistry } from "../src/registry.ts";
import { exactBinding } from "../src/index.ts";
import type { UseResource, PermissionTerms } from "../src/index.ts";
import type { Context } from "../src/contracts.ts";
const c: Context = {
  tenantId: "alpha",
  projectId: "study",
  actor: { id: "owner", kind: "human", roles: ["owner"] },
  purpose: "education",
  requestId: "r",
  now: "2026-01-01T00:00:00Z",
};
const participant: Context = {
  ...c,
  actor: { id: "reporter", kind: "human", roles: ["participant"] },
};
const resource: UseResource = {
  ...exactBinding(
    {
      tenantId: "alpha",
      projectId: "study",
      kind: "image",
      id: "one",
      revision: 1,
    },
    { synthetic: true },
  ),
  requiredConsentSubjects: ["subject"],
};
const terms: PermissionTerms = {
  resource,
  actions: ["reproduce"],
  purposes: ["education"],
  audiences: ["private"],
  validFrom: c.now,
  expiresAt: "2026-02-01T00:00:00Z",
  evidence: { ...resource.ref, kind: "consent-document", id: "proof" },
};
const request = {
  action: "reproduce" as const,
  audience: "private",
  attribution: null,
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
    "CREATE ROLE consent_test_login LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION; GRANT evidence_runtime TO consent_test_login; SET SESSION AUTHORIZATION consent_test_login",
  );
  const db: Database = {
    transaction: (fn) =>
      pg.transaction((q) =>
        fn({
          query: async <T>(sql: string, v?: unknown[]) => ({
            rows: (await q.query(sql, v)).rows as T[],
          }),
        }),
      ),
    close: () => pg.close(),
  };
  t.after(() => pg.close());
  const registry = new PermissionRegistry(db, {
    tenantId: "alpha",
    projectId: "study",
    managerIds: ["owner"],
    participantActors: { subject: "reporter" },
  });
  await registry.registerResource(c, resource, 0);
  return { registry, db };
}
const grantInput = {
  ...terms,
  id: "rights",
  holderId: "creator",
  attribution: null,
  noDerivatives: false,
};
const consentInput = { ...terms, id: "consent", subjectId: "subject" };
test("current stored permissions are evaluated, withdrawal is immutable and queues impact atomically", async (t) => {
  const { registry, db } = await setup(t);
  await registry.grantRights(c, grantInput, "grant");
  await registry.recordConsent(participant, consentInput, "consent");
  assert.equal(
    (
      await registry.evaluate(c, resource.ref, request, {
        rights: ["rights"],
        consents: ["consent"],
      })
    ).allowed,
    true,
  );
  const withdrawn = await registry.withdraw(
    participant,
    "consent",
    "consent",
    1,
    "withdraw",
  );
  assert.equal(withdrawn.ref.revision, 2);
  assert.equal(
    (
      await registry.evaluate(c, resource.ref, request, {
        rights: ["rights"],
        consents: ["consent"],
      })
    ).allowed,
    false,
  );
  await scoped(db, c, async (tx) => {
    const originals = await tx.list("consent");
    assert.equal(originals[0]!.revision, 2);
    assert.ok(verifyAudit(await tx.audits()));
    const job = await tx.claim("impact-worker");
    assert.equal(job?.topic, "permission.withdrawn");
  });
});
test("idempotent grants cannot duplicate records or silently change evidence", async (t) => {
  const { registry } = await setup(t);
  assert.deepEqual(
    await registry.grantRights(c, grantInput, "one"),
    await registry.grantRights(c, grantInput, "one"),
  );
  await assert.rejects(
    registry.grantRights(c, { ...grantInput, holderId: "changed" }, "one"),
    { code: "idempotency_conflict" },
  );
});
test("participant may consent and withdraw only for its bound subject, never grant rights", async (t) => {
  const { registry } = await setup(t);
  await assert.rejects(registry.grantRights(participant, grantInput, "g"), {
    code: "manager_required",
  });
  await assert.rejects(
    registry.recordConsent(
      { ...participant, actor: { ...participant.actor, id: "other" } },
      consentInput,
      "c",
    ),
    { code: "manager_required" },
  );
  await registry.recordConsent(participant, consentInput, "c");
  await assert.rejects(
    registry.withdraw(
      { ...participant, actor: { ...participant.actor, id: "other" } },
      "consent",
      "consent",
      1,
      "w",
    ),
    { code: "manager_required" },
  );
});
test("scope isolation and source policy prevent foreign references and removal of existing consent requirements", async (t) => {
  const { registry } = await setup(t);
  await assert.rejects(
    registry.evaluate(
      { ...c, tenantId: "beta" },
      { ...resource.ref, tenantId: "beta" },
      request,
      { rights: [], consents: [] },
    ),
    { code: "scope_denied" },
  );
  await assert.rejects(
    registry.registerResource(
      c,
      { ...resource, requiredConsentSubjects: [] },
      1,
    ),
    { code: "consent_restriction" },
  );
  await assert.rejects(
    registry.registerResource(
      c,
      {
        ...resource,
        ref: { ...resource.ref, revision: 2 },
        requiredConsentSubjects: [],
      },
      0,
    ),
    { code: "consent_restriction" },
  );
  await assert.rejects(
    registry.registerResource(c, { ...resource, digest: "0".repeat(64) }, 1),
    { code: "resource_changed" },
  );
});
test("unregistered resources unknown permissions and stale withdrawals fail closed", async (t) => {
  const { registry } = await setup(t);
  await assert.rejects(
    registry.recordConsent(
      participant,
      {
        ...consentInput,
        resource: { ...resource, ref: { ...resource.ref, revision: 2 } },
      },
      "bad",
    ),
    { code: "not_found" },
  );
  assert.equal(
    (
      await registry.evaluate(c, resource.ref, request, {
        rights: ["missing"],
        consents: ["missing"],
      })
    ).allowed,
    false,
  );
  await registry.recordConsent(participant, consentInput, "c");
  await assert.rejects(
    registry.withdraw(participant, "consent", "consent", 2, "stale"),
    { code: "revision_conflict" },
  );
});

test('caller context and permission bytes are captured before asynchronous storage waits', async t => {
  const { registry } = await setup(t);
  const context = structuredClone(c);
  const input = structuredClone(grantInput);
  const pending = registry.grantRights(context, input, 'captured');
  (context as { actor: { id: string } }).actor.id = 'tampered-actor';
  input.holderId = 'tampered-holder';
  const grant = await pending;
  assert.equal(grant.recordedBy, 'owner');
  assert.equal(grant.holderId, 'creator');
});
