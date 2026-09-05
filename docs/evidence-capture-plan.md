# Portfolio evidence capture plan

Capture from a clean dev/demo deployment at 1920×1080 or higher. Before saving, replace account IDs, ARNs, access-key fragments, tokens, emails, IPs, request IDs, bucket suffixes, and URLs with labeled placeholders. Keep originals outside the repository; two people should review redaction.

| File | Reproduction step |
|---|---|
| `architecture-diagram.png` | export `architecture-diagram.drawio` |
| `terraform-deploy.png` | show successful isolated plan/apply summary, no identifiers |
| `guardduty-finding.png` | open synthetic demo finding |
| `eventbridge-event.png` | show normalized synthetic finding in DynamoDB |
| `bedrock-investigation.png` | render redacted structured investigation fixture |
| `attack-timeline.png` | render fixture timeline and MITRE labels |
| `blast-radius.png` | render fixture affected-resource report |
| `safety-validation.png` | show decision level, reasons, and evidence IDs |
| `human-approval.png` | show demo approval screen with fake identity |
| `verification-result.png` | show verified demo target state |
| `incident-report.png` | render redacted Markdown report |

Label each image with scenario and UTC timestamp. Record the fixture commit and capture command in adjacent metadata. Only the architecture image is repository-generated now; UI screenshots require a human capture session and must not be fabricated.
