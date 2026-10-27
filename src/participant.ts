import { digest, invariant, nonempty, validTime } from "./contracts.ts";
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
