# 15 — User Protection Mode

**Status:** implementation-backed

Protection mode is the default application surface. It is designed for a Gmail user who should not need to know what SPF or ASN means.

## Result contract

- `SAFE` — the deterministic checks found no material warning sign.
- `SUSPICIOUS` — one or more checks require caution.
- `DANGEROUS` — critical risk signals agree and the message should be treated as an attack.

The result shows the numeric score, a plain-language headline, a small set of reasons, and recommended actions. A reason can be expanded to its technical signal and evidence IDs. Safe actions are conservative: do not click, do not enter credentials, do not transfer money, independently verify, quarantine risky attachments, and report/delete only as a user decision.

The app does not auto-delete, reply, forward, quarantine, change passwords, or change Gmail state. Those are recommendations, not API operations.

## Progressive disclosure

Mailbox card → verdict → why → safe action → text preview → investigator console. Local, external, and AI processing labels remain visible where the boundary matters.
