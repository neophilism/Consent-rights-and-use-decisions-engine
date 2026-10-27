# Consent Rights and Use Decisions Engine

Reusable country-neutral engine. Initial capabilities and limits are documented in [architecture](docs/ARCHITECTURE.md); the canonical work plan is [registry/prs.json](registry/prs.json).

```sh
npm ci
npm run check
```

All research and jurisdiction configuration belong in downstream deployments. Implementation, local tests, CI, merge and live acceptance are separate.

The durable registry exports participant proposal/review/capture operations. See [participant workflow and host boundaries](docs/PARTICIPANTS.md); `./participant` exports the offer/review types and digest profile.

`./participant-http` provides an opt-in host-authenticated JSON handler for that workflow; see [HTTP protocol and deployment requirements](docs/PARTICIPANT_HTTP.md).
