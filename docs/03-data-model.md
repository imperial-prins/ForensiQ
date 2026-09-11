# 03 — Data Model

**Status:** implementation-backed

## `NormalizedEmail`

`backend.models.email.NormalizedEmail` is the provider-neutral input contract:

| Field | Meaning |
|---|---|
| `source_type` | `EML`, `GMAIL_MOCK`, or `GMAIL` |
| `source_message_id` | Provider/local stable identity used for deduplication |
| `account_id` | Source account identifier; nullable for local files |
| `from_address`, `to`, `cc`, `reply_to`, `return_path` | Header identity fields |
| `subject`, `message_id`, `date` | Message metadata |
| `text`, `html` | Extracted content; HTML is never rendered by the preview |
| `attachments` | Filename, MIME type, size, SHA-256, executable flag |
| `received_headers` | Original Received header sequence |
| `mail_servers`, `source_ips` | Parsed routing observations |
| `auth` | SPF, DKIM, DMARC, raw Authentication-Results |
| `source_metadata` | Provider-safe labels/thread metadata |
| `raw_bytes` | In-memory evidence bytes; omitted from public serialization |

`to_analysis_dict()` retains the legacy parser shape so existing analysis modules remain reusable.

## Case report

A persisted case includes:

- identity/status/timestamps/source metadata;
- SHA-256 evidence hash and local evidence path;
- deterministic risk score, level, confidence, engine version, and signals;
- normalized parser data;
- IOCs, intelligence, GeoIP, forensic timeline, graph, and DOT routing graph;
- contradiction records;
- `user_explanation` and `safe_actions`;
- evidence-bounded AI explanation and structured AI evidence.

## SQLite

The `cases` table stores the report JSON plus queryable fields. Migrations add `source_type`, `source_message_id`, and `account_id` to the original scaffold and index them for duplicate Gmail analysis.

The local evidence file is `evidence/{case_id}/original.eml`. The API verifies its hash but does not expose the filesystem path to the frontend.

## Provenance values

- `OBSERVED` — present in the message.
- `DERIVED` — produced by deterministic analysis.
- `EXTERNAL_INTELLIGENCE` — returned by configured enrichment adapters.
- `AI_INTERPRETATION` — validated interpretation constrained to evidence IDs.
- `CROSS_CASE_CORRELATION` — derived from persisted case relationships.
