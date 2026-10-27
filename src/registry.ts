import { scoped } from "@accountability/evidence/database";
import type { Database, UnitOfWork } from "@accountability/evidence/database";
import {
  invariant,
  digest,
  requireScope,
  canonical,
  validTime,
  nonempty,
} from "./contracts.ts";
import type { Context, Ref, Json, Scope } from "./contracts.ts";
import {
  assertRef,
  assertDigest,
  createRightsGrant,
  createConsent,
  withdrawPermission,
  decideUse,
  exactBinding,
  assertContext,
} from "./index.ts";
import type {
  RightsGrant,
  Consent,
  UseResource,
  UseRequest,
  UseDecision,
} from "./index.ts";
import { reviewDigest, validateOfferInput } from "./participant.ts";
import type {
  ConsentOffer,
  ConsentOfferInput,
  ParticipantReview,
} from "./participant.ts";
export type RegistryPolicy = Scope & {
  managerIds: readonly string[];
  participantActors: Readonly<Record<string, string>>;
};
const key = (kind: string, id: string) => digest({ kind, id });
const json = (value: unknown): Json => JSON.parse(canonical(value)) as Json;
export class PermissionRegistry {
  readonly #db: Database;
  readonly #policy: RegistryPolicy;
  constructor(db: Database, policy: RegistryPolicy) {
    this.#db = db;
    this.#policy = structuredClone(policy);
  }
  #manager(c: Context) {
    requireScope(c, this.#policy);
    invariant(
      c.actor.kind === "human" &&
        c.actor.roles.includes("owner") &&
        this.#policy.managerIds.includes(c.actor.id),
      "manager_required",
      "An authenticated listed permission manager is required",
    );
  }
  #participant(c: Context, subject: string) {
    requireScope(c, this.#policy);
    return (
      c.actor.kind === "human" &&
      c.actor.roles.includes("participant") &&
      Object.hasOwn(this.#policy.participantActors, subject) &&
      this.#policy.participantActors[subject] === c.actor.id
    );
  }
  async registerResource(
    c: Context,
    resource: UseResource,
    expectedRevision: number,
  ): Promise<number> {
    c = structuredClone(c);
    resource = structuredClone(resource);
    this.#manager(c);
    assertRef(c, resource.ref);
    assertDigest(resource.digest);
    invariant(
      Array.isArray(resource.requiredConsentSubjects) &&
        new Set(resource.requiredConsentSubjects).size ===
          resource.requiredConsentSubjects.length,
      "invalid_resource",
      "Consent subjects must be explicit and unique",
    );
    return scoped(this.#db, c, async (tx) => {
      const old = await tx.get<UseResource>(
        "permission-resource",
        digest(resource.ref),
      );
      if (old)
        invariant(
          old.value.digest === resource.digest,
          "resource_changed",
          "Exact resource edition cannot change bytes",
        );
      const rootKey = key(resource.ref.kind, resource.ref.id);
      const root = await tx.get<{ subjects: string[] }>(
        "permission-subjects",
        rootKey,
      );
      invariant(
        !root ||
          root.value.subjects.every((x) =>
            resource.requiredConsentSubjects.includes(x),
          ),
        "consent_restriction",
        "Existing consent subjects cannot be removed from this resource or later editions",
      );
      await tx.put("permission-subjects", rootKey, root?.revision ?? 0, {
        subjects: [...resource.requiredConsentSubjects],
      });
      return (
        await tx.put(
          "permission-resource",
          digest(resource.ref),
          expectedRevision,
          resource,
        )
      ).revision;
    });
  }
  async grantRights(
    c: Context,
    input: Parameters<typeof createRightsGrant>[1],
    commandId: string,
  ): Promise<RightsGrant> {
    c = structuredClone(c);
    input = structuredClone(input);
    this.#manager(c);
    return scoped(this.#db, c, (tx) =>
      tx.idempotent(commandId, json(input), async () => {
        await this.#resource(tx, c, input.resource.ref, input.resource.digest);
        const value = createRightsGrant(c, input);
        await tx.put("rights-grant", key("rights-grant", input.id), 0, value);
        return value as unknown as Json;
      }),
    ) as Promise<unknown> as Promise<RightsGrant>;
  }
  async recordConsent(
    c: Context,
    input: Parameters<typeof createConsent>[1],
    commandId: string,
  ): Promise<Consent> {
    c = structuredClone(c);
    input = structuredClone(input);
    if (!this.#participant(c, input.subjectId)) this.#manager(c);
    return scoped(this.#db, c, (tx) =>
      tx.idempotent(commandId, json(input), async () => {
        const resource = await this.#resource(
          tx,
          c,
          input.resource.ref,
          input.resource.digest,
        );
        invariant(
          resource.requiredConsentSubjects.includes(input.subjectId),
          "subject_not_required",
          "Subject is not registered on this resource",
        );
        const value = createConsent(c, input);
        await tx.put("consent", key("consent", input.id), 0, value);
        return value as unknown as Json;
      }),
    ) as Promise<unknown> as Promise<Consent>;
  }
  async withdraw(
    c: Context,
    kind: "consent" | "rights-grant",
    id: string,
    expectedRevision: number,
    commandId: string,
  ): Promise<Consent | RightsGrant> {
    c = structuredClone(c);
    assertContext(c);
    requireScope(c, this.#policy);
    invariant(
      ["consent", "rights-grant"].includes(kind),
      "invalid_kind",
      "Unknown permission kind",
    );
    return scoped(this.#db, c, async (tx) => {
      // Current authority is required for cached withdrawal receipts as well as mutations.
      const authorize = async () => {
        const row = await tx.get<Consent | RightsGrant>(kind, key(kind, id));
        invariant(row, "not_found", "Permission is unavailable");
        requireScope(c, row.value.ref);
        if (
          kind === "rights-grant" ||
          !this.#participant(c, (row.value as Consent).subjectId)
        )
          this.#manager(c);
        return row;
      };
      await authorize();
      return tx.idempotent(
        commandId,
        { kind, id, expectedRevision },
        async () => {
          const record = await authorize();
          invariant(
            record.revision === expectedRevision &&
              record.value.ref.revision === record.revision,
            "revision_conflict",
            "Permission revision changed",
          );
          const value = withdrawPermission(c, record.value);
          await tx.put(kind, key(kind, id), expectedRevision, value);
          await tx.enqueue(
            "permission.withdrawn",
            {
              kind,
              id,
              revision: value.ref.revision,
              resource: record.value.resource.ref as unknown as Json,
            },
            digest({ kind, id, revision: value.ref.revision }),
          );
          return value as unknown as Json;
        },
      );
    }) as Promise<unknown> as Promise<Consent | RightsGrant>;
  }
  async evaluate(
    c: Context,
    ref: Ref,
    request: UseRequest,
    ids: { rights: readonly string[]; consents: readonly string[] },
  ): Promise<UseDecision> {
    c = structuredClone(c);
    ref = structuredClone(ref);
    request = structuredClone(request);
    ids = structuredClone(ids);
    requireScope(c, this.#policy);
    invariant(
      c.actor.roles.some((r) =>
        ["viewer", "researcher", "operator", "owner", "rights:read"].includes(
          r,
        ),
      ),
      "read_denied",
      "Permission evaluation requires scoped research access",
    );
    assertRef(c, ref);
    invariant(
      ids.rights.length <= 100 && ids.consents.length <= 100,
      "too_many_permissions",
      "At most100grant and100consent IDs per decision",
    );
    return scoped(this.#db, c, async (tx) => {
      const resource = await this.#resource(tx, c, ref);
      const rights: RightsGrant[] = [],
        consents: Consent[] = [];
      for (const id of ids.rights) {
        const row = await tx.get<RightsGrant>(
          "rights-grant",
          key("rights-grant", id),
        );
        if (row) rights.push(row.value);
      }
      for (const id of ids.consents) {
        const row = await tx.get<Consent>("consent", key("consent", id));
        if (row) consents.push(row.value);
      }
      const decision = decideUse(c, resource, request, rights, consents);
      await tx.audit("permission.evaluated", {
        resource: ref as unknown as Json,
        allowed: decision.allowed,
        decisionHash: digest(decision),
      });
      return decision;
    });
  }
  #requireParticipant(c: Context, subjectId: string): void {
    assertContext(c);
    invariant(
      this.#participant(c, subjectId),
      "participant_required",
      "Only the authenticated participant bound to this subject may respond",
    );
  }
  async #offer(tx: UnitOfWork, c: Context, id: string) {
    nonempty(id, "Offer id", 200);
    const row = await tx.get<ConsentOffer>(
      "consent-offer",
      key("consent-offer", id),
    );
    // A missing offer and an offer belonging to another participant have the same result.
    invariant(
      row && this.#participant(c, row.value.subjectId),
      "offer_unavailable",
      "Participant offer is unavailable",
    );
    invariant(
      row.value.ref.revision === row.revision,
      "revision_conflict",
      "Stored offer revision is inconsistent",
    );
    return row;
  }
  async createOffer(
    c: Context,
    input: ConsentOfferInput,
    commandId: string,
  ): Promise<ConsentOffer> {
    c = structuredClone(c);
    input = structuredClone(input);
    assertContext(c);
    this.#manager(c);
    invariant(
      Object.hasOwn(this.#policy.participantActors, input.subjectId),
      "participant_unbound",
      "An authenticated participant mapping is required",
    );
    return scoped(this.#db, c, (tx) =>
      tx.idempotent(
        commandId,
        json({
          operation: "create-consent-offer",
          purpose: c.purpose,
          actorKind: c.actor.kind,
          input,
        }),
        async () => {
          validateOfferInput(input, c.now);
          // Reuse domain term validation; this proposed value is never stored as consent.
          createConsent(c, {
            ...input.terms,
            id: input.id,
            subjectId: input.subjectId,
          });
          const resource = await this.#resource(
            tx,
            c,
            input.terms.resource.ref,
            input.terms.resource.digest,
          );
          invariant(
            resource.requiredConsentSubjects.includes(input.subjectId),
            "subject_not_required",
            "Subject is not registered on this resource",
          );
          const offer: ConsentOffer = {
            ...input,
            ref: {
              tenantId: c.tenantId,
              projectId: c.projectId,
              kind: "consent-offer",
              id: input.id,
              revision: 1,
            },
            createdAt: c.now,
            createdBy: c.actor.id,
            status: "offered",
            resolvedAt: null,
            resolvedBy: null,
            consent: null,
          };
          await tx.put(
            "consent-offer",
            key("consent-offer", input.id),
            0,
            offer,
          );
          return json(offer);
        },
      ),
    ) as Promise<unknown> as Promise<ConsentOffer>;
  }
  async reviewOffer(c: Context, id: string): Promise<ParticipantReview> {
    c = structuredClone(c);
    assertContext(c);
    requireScope(c, this.#policy);
    invariant(
      c.actor.kind === "human" && c.actor.roles.includes("participant"),
      "participant_required",
      "Authenticated participant access is required",
    );
    return scoped(this.#db, c, async (tx) => {
      const { value: offer } = await this.#offer(tx, c, id);
      let consent: Consent | null = null;
      if (offer.consent) {
        const row = await tx.get<Consent>(
          "consent",
          key("consent", offer.consent.ref.id),
        );
        invariant(
          row && row.value.subjectId === offer.subjectId,
          "consent_unavailable",
          "Current consent is unavailable",
        );
        consent = row.value;
      }
      return {
        offer,
        reviewDigest: reviewDigest(offer),
        responseOpen:
          offer.status === "offered" &&
          validTime(c.now) < validTime(offer.responseExpiresAt),
        consent,
        warnings: [
          "Acknowledgement records a participant assertion; it does not prove reading, comprehension, capacity or freedom from coercion.",
          "Consent is separate from rights, legal review and release authorization. Withdrawal cannot recall copies already obtained.",
        ],
      };
    });
  }
  async respondToOffer(
    c: Context,
    input: Readonly<{
      offerId: string;
      expectedRevision: number;
      reviewDigest: string;
      response: "accept" | "decline";
      acknowledged: boolean;
    }>,
    commandId: string,
  ): Promise<ConsentOffer> {
    c = structuredClone(c);
    input = structuredClone(input);
    assertContext(c);
    requireScope(c, this.#policy);
    invariant(
      c.actor.kind === "human" && c.actor.roles.includes("participant"),
      "participant_required",
      "Authenticated participant access is required",
    );
    nonempty(input.offerId, "Offer id", 200);
    assertDigest(input.reviewDigest);
    invariant(
      Number.isSafeInteger(input.expectedRevision) &&
        input.expectedRevision > 0,
      "invalid_revision",
      "A viewed positive offer revision is required",
    );
    invariant(
      Object.keys(input).length === 5 &&
        [
          "offerId",
          "expectedRevision",
          "reviewDigest",
          "response",
          "acknowledged",
        ].every((k) => Object.hasOwn(input, k)) &&
        typeof input.acknowledged === "boolean",
      "invalid_response",
      "Exact response fields and an explicit boolean acknowledgement are required",
    );
    invariant(
      input.response === "accept" || input.response === "decline",
      "invalid_response",
      "Explicit response is required",
    );
    invariant(
      input.response !== "accept" || input.acknowledged === true,
      "acknowledgement_required",
      "Acceptance requires explicit acknowledgement of the exact disclosure and terms",
    );
    return scoped(this.#db, c, async (tx) => {
      // Recheck present participant authority even when returning a cached response.
      await this.#offer(tx, c, input.offerId);
      return tx.idempotent(
        commandId,
        json({
          operation: "respond-consent-offer",
          purpose: c.purpose,
          actorKind: c.actor.kind,
          input,
        }),
        async () => {
          const row = await this.#offer(tx, c, input.offerId);
          const offer = row.value;
          this.#requireParticipant(c, offer.subjectId);
          invariant(
            row.revision === input.expectedRevision &&
              reviewDigest(offer) === input.reviewDigest,
            "review_changed",
            "Review the current offer before responding",
          );
          invariant(
            offer.status === "offered",
            "offer_closed",
            "The offer already has a response or was cancelled",
          );
          invariant(
            validTime(c.now) < validTime(offer.responseExpiresAt),
            "offer_expired",
            "The response window has ended",
          );
          let consentBinding = null;
          if (input.response === "accept") {
            await this.#resource(
              tx,
              c,
              offer.terms.resource.ref,
              offer.terms.resource.digest,
            );
            const consent = createConsent(c, {
              ...offer.terms,
              id: digest({ profile: "offer-consent-v1", offer: offer.ref }),
              subjectId: offer.subjectId,
            });
            await tx.put("consent", key("consent", consent.ref.id), 0, consent);
            consentBinding = exactBinding(consent.ref, consent);
          }
          const next: ConsentOffer = {
            ...offer,
            ref: { ...offer.ref, revision: row.revision + 1 },
            status: input.response === "accept" ? "accepted" : "declined",
            resolvedAt: c.now,
            resolvedBy: c.actor.id,
            consent: consentBinding,
          };
          await tx.put(
            "consent-offer",
            key("consent-offer", input.offerId),
            row.revision,
            next,
          );
          await tx.audit(
            "participant.offer.responded",
            json({
              offer: next.ref,
              response: input.response,
              reviewedDigest: input.reviewDigest,
              acknowledged: input.acknowledged,
              consent: next.consent,
            }),
          );
          await tx.enqueue(
            "participant.offer.responded",
            json({ offer: next.ref, consent: next.consent }),
            digest(next.ref),
          );
          return json(next);
        },
      );
    }) as Promise<unknown> as Promise<ConsentOffer>;
  }
  async cancelOffer(
    c: Context,
    id: string,
    expectedRevision: number,
    commandId: string,
  ): Promise<ConsentOffer> {
    c = structuredClone(c);
    assertContext(c);
    this.#manager(c);
    return scoped(this.#db, c, (tx) =>
      tx.idempotent(
        commandId,
        json({
          operation: "cancel-consent-offer",
          purpose: c.purpose,
          actorKind: c.actor.kind,
          id,
          expectedRevision,
        }),
        async () => {
          const row = await tx.get<ConsentOffer>(
            "consent-offer",
            key("consent-offer", id),
          );
          invariant(row, "offer_unavailable", "Offer is unavailable");
          invariant(
            row.revision === expectedRevision,
            "revision_conflict",
            "Offer changed",
          );
          invariant(
            row.value.status === "offered",
            "offer_closed",
            "Only an unanswered offer can be cancelled",
          );
          const next: ConsentOffer = {
            ...row.value,
            ref: { ...row.value.ref, revision: row.revision + 1 },
            status: "cancelled",
            resolvedAt: c.now,
            resolvedBy: c.actor.id,
          };
          await tx.put(
            "consent-offer",
            key("consent-offer", id),
            row.revision,
            next,
          );
          return json(next);
        },
      ),
    ) as Promise<unknown> as Promise<ConsentOffer>;
  }
  async #resource(
    tx: UnitOfWork,
    c: Context,
    ref: Ref,
    sha256?: string,
  ): Promise<UseResource> {
    assertRef(c, ref);
    const record = await tx.get<UseResource>(
      "permission-resource",
      digest(ref),
    );
    invariant(
      record,
      "not_found",
      "Resource permission policy is not registered",
    );
    requireScope(c, record.value.ref);
    invariant(
      digest(record.value.ref) === digest(ref) &&
        (sha256 === undefined || record.value.digest === sha256),
      "resource_changed",
      "Resource binding changed",
    );
    return record.value;
  }
}
