# ForensiQ malicious campaign demo

This is a **synthetic, inert** campaign for first-round evaluation. It contains no real malware, the attachment is harmless text stored with a `.zip` filename so the parser can demonstrate attachment-risk handling, and ForensiQ never visits URLs found in email content.

## Primary message

- **File:** `data/samples/forensiq_demo_credential_campaign.eml`
- **From:** `"Microsoft 365 Security" <security@microsoft365-alerts.top>`
- **Reply-To:** `account-recovery@account-recovery.top`
- **Subject:** `CRITICAL: Microsoft 365 session expires - verify immediately`
- **Defanged indicators:** `hxxp://microsoft-login-verify[.]top/session`, `hxxp://185.220.101[.]5/m365/verify`, source IP `185.220.101.5`
- **Attachment:** `Microsoft_Security_Update.zip` — harmless synthetic text, deliberately classified as a risky archive by the demo parser

## How to demonstrate it

1. Start ForensiQ with `GMAIL_MODE=mock`.
2. Click **Connect Gmail** and confirm the **DEMO MAILBOX** label.
3. Run **Scan recent emails**.
4. Open **CRITICAL: Microsoft 365 session expires - verify immediately**.
5. Select **Investigate deeper**.
6. Walk through the tabs in this order:
   **Overview → Authentication → Indicators → Intelligence → GeoIP → Timeline → Graph → Evidence → Related emails**.

## What each investigator tab demonstrates

| Tab | Visible capability in this case |
|---|---|
| Overview | `DANGEROUS`, risk `100/100`, explainable signals, AI fallback constrained to deterministic evidence, and conservative actions. |
| Authentication | SPF, DKIM, and DMARC failures plus From/Reply-To/Return-Path identity mismatch. |
| Indicators | Extracted public IPs, domains, URLs, and email addresses with source and evidence IDs. |
| Intelligence | Clearly labeled `MOCK` passive lookups; the synthetic IP and abuse-style domains receive malicious matches. URLs are not fetched. |
| GeoIP | Observed infrastructure geography for `185.220.101.5` (`Frankfurt, Germany`, `AS-MOCK`). This is not claimed to be the attacker’s location. |
| Timeline | Two parsed Received-header hops, timestamps, relay names, protocol, and observed IPs. |
| Graph | Email → sender → reply/return path → domains/URLs → mail servers → IP → GeoIP/ASN relationships. |
| Evidence | Original evidence SHA-256 hash, source message ID, provenance chain, and the AI untrusted-content policy. |
| Related emails | Shared campaign infrastructure across the primary message and the companion SharePoint/voicemail messages. |

## Related campaign messages

The mock mailbox also includes these companions so correlation is visible after scanning:

- `data/samples/forensiq_demo_sharepoint_campaign.eml`
- `data/samples/forensiq_demo_voicemail_campaign.eml`

They intentionally share the synthetic sender domain, reply infrastructure, verification domain, and source IP. In a fresh local database, the primary case forms a three-message cluster. If an existing local demo database already contains older analyzed cases sharing `185.220.101.5`, the Related emails view may display those historical cases in the same explainable cluster as well.

## Upload variant

The primary file can also be uploaded through **Upload .eml**. It follows the same normalization, forensics, intelligence, risk, evidence, and investigator pipeline as the mock Gmail message, but the source is shown as `EML` instead of `GMAIL_MOCK`.
