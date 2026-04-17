# Tool Rename History

Past renames for reference. Users upgrading from older docs or
external blog posts should use the NEW names.

| Old Name              | New Name                 | Rationale                          | Commit  | Date       |
|-----------------------|--------------------------|------------------------------------|---------|------------|
| backtest_strategy     | historical_price_analyzer| Factual framing; advisory-sounding | 78301d6 | 2026-04-17 |
| portfolio_rebalance   | portfolio_analysis       | Same                               | 78301d6 | 2026-04-17 |
| options_strategy      | options_payoff_builder   | Same                               | 78301d6 | 2026-04-17 |
| pre_trade_check       | order_risk_report        | "check" -> "report" (factual)      | c27f504 | 2026-04-17 |
| tax_harvest_analysis  | tax_loss_analysis        | "harvest" connotes action          | c27f504 | 2026-04-17 |

All renamed tool descriptions now end with "Not investment advice."
to reinforce tool-provider (not advisor) positioning under SEBI
Path 1.

## Aliases

We do NOT maintain server-side aliases. Old names return
"tool not found" errors. The rename is a breaking change for
clients that hardcoded the old name — update to the new name.

If a rename breaks your workflow, file an issue (link to
.github/ISSUE_TEMPLATE) with "rename-alias-request" in the title.
