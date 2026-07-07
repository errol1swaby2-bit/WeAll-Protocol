# Accessibility reviewer checklist

Status: **basic source-level accessibility posture exists; full WCAG compliance is not claimed**.

This checklist gives reviewers a deterministic place to inspect accessibility intent for the pre-public-testnet frontend. It does not claim completed WCAG conformance, completed assistive-technology testing, or completed manual accessibility review.

## Current checklist

| Area | Current source-level expectation | Current coverage | Remaining gap |
|---|---|---|---|
| Keyboard navigation | App shell exposes a skip link and focusable navigation targets. | `web/scripts/test_accessibility_source.mjs` checks skip link and main target. | Manual keyboard walkthrough still required. |
| Visible focus intent | CSS includes `:focus-visible` styling. | Source check verifies focus-visible rule. | Browser contrast/focus screenshots still required. |
| Form labels / accessible names | Critical settings/forms should use labels or accessible descriptions. | Source check verifies labels in settings and described-by usage. | Expand checks across every form before claiming WCAG. |
| Status messages | Async status/error states use live regions or alert roles where practical. | Source check covers node dashboard/error banner live/alert patterns. | Rendered assistive-tech validation still required. |
| Contrast intent | UI should avoid low-contrast text and expose clear status copy. | Checklist/documented intent only. | Full automated contrast audit not yet installed. |
| Error copy | Errors should be actionable and not only technical codes. | Error banner has alert semantics; reviewer-critical copy checks cover boundaries. | Manual content QA still required. |
| Loading states | Loading and waiting states should communicate what is happening. | Source-level UI patterns exist. | More rendered E2E assertions needed. |
| Disabled/locked economics copy | Wallet/economics pages must explain locked economics clearly. | Reviewer-critical source check covers locked wallet/economics copy. | Rendered browser validation remains useful. |
| Color-only information | Critical status should use text/icons, not color alone. | Checklist intent; status components include text labels. | Full component audit remains open. |

## Automated check

```bash
cd web
npm run test:accessibility-source
npm run test:reviewer-critical-source
```

If `node_modules` is absent, run the scripts directly with system Node where possible:

```bash
node scripts/test_accessibility_source.mjs
node scripts/test_reviewer_critical_flows_source.mjs
```

## Non-claims

The repository must not claim full WCAG compliance until a future patch adds rendered/browser accessibility checks, contrast evidence, keyboard walkthrough transcript, assistive-technology notes, and issue remediation evidence bound to a specific commit.
