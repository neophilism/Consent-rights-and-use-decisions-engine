import {
  canonical,
  digest,
  invariant,
  nonempty,
  validTime,
} from "./contracts.ts";
import type { Ref } from "./contracts.ts";
import type { Consent, ExactResource, PermissionTerms } from "./index.ts";

/** A proposal is not consent, a rights grant, or permission to publish. */
export type ConsentOfferInput = Readonly<{
  id: string;
  subjectId: string;
  terms: PermissionTerms;
  disclosure: string;
  responseExpiresAt: string;
}>;
export type ConsentOffer = ConsentOfferInput &
  Readonly<{
    ref: Ref;
    createdAt: string;
    createdBy: string;
    status: "offered" | "accepted" | "declined" | "cancelled";
    resolvedAt: string | null;
    resolvedBy: string | null;
    consent: ExactResource | null;
  }>;
export type ParticipantReview = Readonly<{
  offer: ConsentOffer;
  reviewDigest: string;
  responseOpen: boolean;
  consent: Consent | null;
  warnings: readonly string[];
}>;

export function reviewDigest(offer: ConsentOffer): string {
  return digest({ profile: "participant-consent-offer-v1", offer });
}
export function validateOfferInput(
  input: ConsentOfferInput,
  now: string,
): void {
  // Reject unexpected caller data instead of echoing it into participant-visible records.
  canonical(input);
  const exact = (value: unknown, keys: readonly string[]) => {
    invariant(
      value !== null &&
        typeof value === "object" &&
        !Array.isArray(value) &&
        Object.keys(value).length === keys.length &&
        keys.every((k) => Object.hasOwn(value, k)),
      "invalid_offer",
      "Offer fields must match the declared profile exactly",
    );
  };
  exact(input, ["id", "subjectId", "terms", "disclosure", "responseExpiresAt"]);
  exact(input.terms, [
    "resource",
    "actions",
    "purposes",
    "audiences",
    "validFrom",
    "expiresAt",
    "evidence",
  ]);
  exact(input.terms.resource, ["ref", "digest"]);
  for (const ref of [input.terms.resource.ref, input.terms.evidence])
    exact(ref, ["tenantId", "projectId", "kind", "id", "revision"]);
  for (const values of [
    input.terms.actions,
    input.terms.purposes,
    input.terms.audiences,
  ])
    invariant(
      Array.isArray(values) && values.length <= 32,
      "invalid_offer",
      "Each term list is bounded to 32 entries",
    );
  nonempty(input.id, "Offer id", 200);
  nonempty(input.subjectId, "Subject id", 200);
  nonempty(input.disclosure, "Participant disclosure", 16000);
  invariant(
    validTime(input.responseExpiresAt) > validTime(now) &&
      validTime(input.responseExpiresAt) <= validTime(input.terms.expiresAt),
    "invalid_offer_expiry",
    "Response expiry must be in the future and no later than permission expiry",
  );
}
