# 11 — UI/UX Flow

**Status:** implementation-backed

## Protection mode

1. Open `My email security`.
2. Connect Gmail or upload an `.eml` without needing security knowledge.
3. See a recent/relevant mailbox list and clear `SAFE`, `SUSPICIOUS`, or `DANGEROUS` labels.
4. Select or analyze a message.
5. See score, plain-language headline, reasons, and safe actions.
6. Use `View email` for a read-only text preview.
7. Choose `Investigate deeper` for the same persisted case.

Mock mode is always labeled `DEMO MAILBOX`/`DEMO / MOCK MAILBOX`. The privacy banner distinguishes local observation, passive lookup, and AI interpretation.

## Investigator mode

The same case is organized into Overview, Authentication, Indicators, Intelligence, GeoIP, Timeline, Graph, Evidence, and Related emails tabs. Jargon is kept out of the initial protection result but remains available progressively.

## Interaction rules

- A user action is required to analyze a selected message or run a bounded scan.
- Buttons never mutate Gmail.
- Email HTML is not rendered as active content.
- Errors are surfaced in a bounded banner rather than silently treated as safe.
- The interface favors readable cards and evidence links over a dashboard full of unexplained metrics.
