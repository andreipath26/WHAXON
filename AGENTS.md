# WHAXON repository instructions

Before changing V2 UI routes, templates, designs, browser tests, or UI-facing API contracts, read and apply [the UI crosswalk](docs/V2_UI_MANDATORY_CROSSWALK.md). Preserve supplied design inputs and the product's supported desktop scope.

## Delivery order

Complete the agreed V2 engine, V2 UI, and remaining v1.0 implementation scope before starting final external validation. Run unit, integration, static, and browser tests continuously during implementation; these are internal development checks and must not be postponed.

After the agreed implementation scope is complete and internal checks pass, run the deferred qualification work: controlled real-target testing with explicit authorization, independent review, manual accessibility review, and production-like install, upgrade, rollback, and recovery exercises. Deploy to production only after the release candidate passes that qualification.

Do not represent historical repository text as an operator decision without a verifiable approval record. Track evidence, limitations, and current status in the canonical roadmap and subject masters.
