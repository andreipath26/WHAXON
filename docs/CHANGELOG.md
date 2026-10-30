## 2026-10-30 (UI Pass 2 - workflow controls and live data)

**Added**
- Findings filters now apply to the real finding rows and show live counts. Findings CSV export downloads the loaded engagement findings.
- Findings target summary is derived from actual targets; the previous fabricated mini attack-surface graphic and fixed counts were removed.
- The Findings slide-over now carries job/sequence identity so Validate and Retest actions are actually available for persisted rows; successful actions reload the data.
- The command palette searches visible pages, the loaded tool catalog, and loaded findings, and navigates to the selected result.
- The shell loads the active engagement name from scope and current Metasploit availability from the API. Nonfunctional sort/group/saved-view controls and the fake workspace switch action were removed.
- The Report page now displays a live engagement snapshot. Fabricated recent-report and known-vulnerability preview rows were removed because no report-history backend exists.
- The Catalog adapter column now comes from the adapter registry, not a blank placeholder.
- Out-of-scope run attempts show the actual target/tool and remain blocked. Operators may log the blocked attempt; the UI explicitly states that logging does not authorize execution.

**Tests**
- Added Playwright coverage for Findings filters/export/validation controls, shell status, command palette, Catalog adapter state, report summary/download, and blocked scope attempts.

