import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  postgresDatabase,
  scoped,
  verifyAudit,
} from "@accountability/evidence/database";
import type { Database } from "@accountability/evidence/database";
import { PermissionRegistry } from "../src/registry.ts";
import { exactBinding } from "../src/index.ts";
import type { Context } from "../src/contracts.ts";
import type { ConsentOfferInput } from "../src/participant.ts";
// Intentionally refuses arbitrary or persistent database targets. CI owns this empty fixture only.
const supplied = process.env.CONSENT_TEST_ADMIN_URL;
assert.ok(
  process.env.CONSENT_TEST_DISPOSABLE_POSTGRES === "1" && supplied,
  "Explicit disposable PostgreSQL fixture configuration required",
);
const url = new URL(supplied);
assert.ok(
  ["postgres:", "postgresql:"].includes(url.protocol) &&
    ["localhost", "127.0.0.1"].includes(url.hostname) &&
    url.pathname === "/consent_ci" &&
    url.username === "postgres" &&
    !url.search &&
    !url.hash,
  "Only the designated empty loopback fixture is accepted",
);
const admin = postgresDatabase(url.toString());
before(async () => {
  await admin.transaction(async (q) => {
    assert.equal(
      (
        await q.query<{ fresh: boolean }>(
          "SELECT to_regclass('public.evidence_project') IS NULL AS fresh",
        )
      ).rows[0]!.fresh,
      true,
      "Fixture must be empty; never reset a database here",
    );
    const migration = await readFile(
      new URL(
        "../migrations/001_foundation.sql",
        import.meta.resolve("@accountability/evidence/database"),
      ),
      "utf8",
    );
    assert.equal(migration.match(/^BEGIN;$/gm)?.length, 1);
    assert.equal(migration.match(/^COMMIT;$/gm)?.length, 1);
    // The SDK transaction owns BEGIN/COMMIT; every actual migration statement is unchanged.
    await q.query(migration.replace(/^BEGIN;$/m, "").replace(/^COMMIT;$/m, ""));
    await q.query(
      "CREATE ROLE consent_network_login LOGIN PASSWORD 'fixture-runtime-only' NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION; GRANT evidence_runtime TO consent_network_login",
    );
  });
});
after(() => admin.close());

function gate() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { resolve, promise };
}

async function fixture(t: test.TestContext, id: string) {
  const manager: Context = {
    tenantId: "fiction",
    projectId: id,
    actor: { id: "manager", kind: "human", roles: ["owner"] },
    purpose: "education",
    requestId: "fixture",
    now: "2026-01-01T00:00:00Z",
  };
  const participant: Context = {
    ...manager,
    actor: { id: "person", kind: "human", roles: ["participant"] },
  };
  const policy = {
    tenantId: manager.tenantId,
    projectId: id,
    managerIds: ["manager"],
    participantActors: { subject: "person" },
  };
  function connect(label: string) {
    const u = new URL(url);
    u.username = "consent_network_login";
    u.password = "fixture-runtime-only";
    u.searchParams.set("application_name", id + "-" + label);
    const raw = postgresDatabase(u.toString());
    let closed = false;
    const db: Database = {
      transaction: raw.transaction.bind(raw),
      close: async () => {
        if (!closed) {
          closed = true;
          await raw.close();
        }
      },
    };
    t.after(() => db.close());
    return db;
  }
  const a = connect("a"),
    b = connect("b");
  const sessions = await Promise.all(
    [a, b].map((db) =>
      db.transaction((q) =>
        q.query<{ pid: number; login: string }>(
          "SELECT pg_backend_pid() AS pid, session_user AS login",
        ),
      ),
    ),
  );
  assert.notEqual(sessions[0]!.rows[0]!.pid, sessions[1]!.rows[0]!.pid);
  assert.ok(
    sessions.every((r) => r.rows[0]!.login === "consent_network_login"),
  );
  const sa = new PermissionRegistry(a, policy),
    sb = new PermissionRegistry(b, policy);
  const resource = {
    ...exactBinding(
      {
        tenantId: manager.tenantId,
        projectId: id,
        kind: "image",
        id: "synthetic",
        revision: 1,
      },
      { fictional: true },
    ),
    requiredConsentSubjects: ["subject"],
  };
  const input: ConsentOfferInput = {
    id: "offer",
    subjectId: "subject",
    disclosure:
      "Optional use of a fictional image for private educational review.",
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
        id: "fictional-terms",
      },
    },
  };
  await sa.registerResource(manager, resource, 0);
  await sa.createOffer(manager, input, "create-offer");
  await sa.grantRights(
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
  const review = await sa.reviewOffer(participant, "offer");
  const command = {
    offerId: "offer",
    expectedRevision: 1,
    reviewDigest: review.reviewDigest,
    response: "accept" as const,
    acknowledged: true,
  };
  return {
    a,
    b,
    sa,
    sb,
    manager,
    participant,
    policy,
    resource,
    input,
    command,
    connect,
    id,
  };
}
async function observedLock(application: string) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    const r = await admin.transaction((q) =>
      q.query<{ blocked: boolean }>(
        "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock' AND cardinality(pg_blocking_pids(pid))>0) AS blocked",
        [application],
      ),
    );
    if (r.rows[0]!.blocked) return;
    await new Promise((r) => setTimeout(r, 10));
  }
  assert.fail("Must directly observe PostgreSQL backend lock contention");
}
for (const contender of ["decline", "cancel"] as const) {
  test(
    `independent participant acceptance and ${contender} commit one terminal offer`,
    { timeout: 20000 },
    async (t) => {
      const f = await fixture(t, "consent-race-" + contender);
      const outcomes = await Promise.allSettled([
        f.sa.respondToOffer(f.participant, f.command, "accept"),
        contender === "decline"
          ? f.sb.respondToOffer(
              f.participant,
              { ...f.command, response: "decline", acknowledged: false },
              "decline",
            )
          : f.sb.cancelOffer(f.manager, "offer", 1, "cancel"),
      ]);
      assert.equal(outcomes.filter((r) => r.status === "fulfilled").length, 1);
      const review = await f.sb.reviewOffer(f.participant, "offer");
      assert.notEqual(review.offer.status, "offered");
      await scoped(f.b, f.manager, async (tx) => {
        const accepted = review.offer.status === "accepted",
          cancelled = review.offer.status === "cancelled";
        assert.equal((await tx.list("consent")).length, accepted ? 1 : 0);
        assert.equal(
          (await tx.audits()).filter(
            (a) => a.type === "participant.offer.responded",
          ).length,
          cancelled ? 0 : 1,
        );
        assert.ok(verifyAudit(await tx.audits()));
        const topics: string[] = [];
        for (;;) {
          const e = await tx.claim("fixture-inspector");
          if (!e) break;
          topics.push(e.topic);
          await tx.acknowledge(e);
        }
        assert.equal(
          topics.filter((topic) => topic === "participant.offer.responded")
            .length,
          cancelled ? 0 : 1,
        );
      });
    },
  );
}
for (const kind of ["consent", "rights-grant"] as const) {
  test(
    `evaluation loads withdrawn ${kind} after a directly observed project-lock wait`,
    { timeout: 20000 },
    async (t) => {
      const f = await fixture(t, "evaluation-lock-" + kind);
      const accepted = await f.sa.respondToOffer(
        f.participant,
        f.command,
        "accept",
      );
      const consentId = accepted.consent!.ref.id;
      const request = {
          action: "reproduce" as const,
          audience: "private",
          attribution: null,
        },
        ids = { rights: ["rights"], consents: [consentId] };
      assert.equal(
        (await f.sb.evaluate(f.manager, f.resource.ref, request, ids)).allowed,
        true,
      );
      const locked = gate(),
        release = gate();
      // The real withdrawal callback finished, but its owning transaction still holds the project lock before COMMIT.
      const delayed: Database = {
        transaction: (fn) =>
          f.a.transaction(async (q) => {
            const value = await fn(q);
            locked.resolve();
            await release.promise;
            return value;
          }),
        close: async () => {},
      };
      const hold = new PermissionRegistry(delayed, f.policy).withdraw(
        kind === "consent" ? f.participant : f.manager,
        kind,
        kind === "consent" ? consentId : "rights",
        1,
        "withdraw",
      );
      let pending: ReturnType<PermissionRegistry["evaluate"]> | undefined;
      try {
        await Promise.race([locked.promise, hold]);
        pending = f.sb.evaluate(f.manager, f.resource.ref, request, ids);
        const outcome = pending.then(
          (value) => ({ value }),
          (error) => ({ error }),
        );
        await observedLock(f.id + "-b");
        release.resolve();
        await hold;
        const result = await outcome;
        assert.ok("value" in result);
        assert.equal(
          result.value.allowed,
          false,
          "A withdrawn permission must not authorize a post-lock decision",
        );
        const review = await f.sb.reviewOffer(f.participant, "offer");
        assert.equal(review.consent?.ref.revision, kind === "consent" ? 2 : 1);
      } finally {
        release.resolve();
        await hold;
        await pending?.catch(() => {});
      }
    },
  );
}

test(
  "lost acceptance acknowledgement survives a fresh pool and replay cannot revive withdrawal",
  { timeout: 20000 },
  async (t) => {
    const f = await fixture(t, "consent-lost-ack");
    let lost = false;
    const flaky: Database = {
      transaction: async (fn) => {
        const value = await f.a.transaction(fn);
        if (!lost) {
          lost = true;
          throw Error("fixture lost post-COMMIT acknowledgement");
        }
        return value;
      },
      close: async () => {},
    };
    await assert.rejects(
      new PermissionRegistry(flaky, f.policy).respondToOffer(
        f.participant,
        f.command,
        "accept",
      ),
    );
    assert.equal(lost, true);
    await f.a.close();
    const fresh = f.connect("fresh"),
      reopened = new PermissionRegistry(fresh, f.policy);
    const receipt = await reopened.respondToOffer(
      f.participant,
      f.command,
      "accept",
    );
    assert.equal(receipt.status, "accepted");
    await reopened.withdraw(
      f.participant,
      "consent",
      receipt.consent!.ref.id,
      1,
      "withdraw",
    );
    assert.deepEqual(
      await reopened.respondToOffer(f.participant, f.command, "accept"),
      receipt,
    );
    assert.equal(
      (await reopened.reviewOffer(f.participant, "offer")).consent?.ref
        .revision,
      2,
    );
    assert.equal(
      (
        await reopened.evaluate(
          f.manager,
          f.resource.ref,
          { action: "reproduce", audience: "private", attribution: null },
          { rights: ["rights"], consents: [receipt.consent!.ref.id] },
        )
      ).allowed,
      false,
    );
    await scoped(fresh, f.manager, async (tx) => {
      assert.equal((await tx.list("consent")).length, 1);
      assert.ok(verifyAudit(await tx.audits()));
      assert.equal(
        (await tx.audits()).filter(
          (a) => a.type === "participant.offer.responded",
        ).length,
        1,
      );
    });
  },
);
test(
  "permission network sessions reject privileged roles and isolate stored scopes",
  { timeout: 20000 },
  async (t) => {
    const f = await fixture(t, "consent-isolation");
    await assert.rejects(
      new PermissionRegistry(admin, f.policy).reviewOffer(
        f.participant,
        "offer",
      ),
      { code: "unsafe_database_role" },
    );
    const lowered: Database = {
      transaction: (fn) =>
        admin.transaction(async (q) => {
          await q.query("SET LOCAL ROLE evidence_runtime");
          return fn(q);
        }),
      close: async () => {},
    };
    await assert.rejects(
      new PermissionRegistry(lowered, f.policy).reviewOffer(
        f.participant,
        "offer",
      ),
      { code: "unsafe_database_role" },
    );
    await assert.rejects(
      f.b.transaction((q) =>
        q.query("CREATE TABLE public.consent_forbidden(id integer)"),
      ),
    );
    await assert.rejects(f.b.transaction((q) => q.query("SET ROLE postgres")));
    assert.equal(
      (
        await f.b.transaction(async (q) => {
          await q.query("SET LOCAL ROLE evidence_runtime");
          return q.query("SELECT * FROM public.evidence_record");
        })
      ).rows.length,
      0,
    );
    await scoped(f.b, { ...f.manager, projectId: "unrelated" }, async (tx) =>
      assert.deepEqual(await tx.list("consent-offer"), []),
    );
    assert.equal(
      (await f.sb.reviewOffer(f.participant, "offer")).offer.ref.revision,
      1,
    );
  },
);
