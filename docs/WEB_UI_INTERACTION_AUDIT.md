# WHAXON Web UI Interaction Audit

## Status legend
- **PASS** — wired, verified in a browser, has a passing test
- **WIRED** — wired to a real backend, not yet verified in a browser
- **MOCKUP** — hardcoded data, no backend
- **HIDDEN** — mockup, sidebar item hidden until backend exists
- **BLOCKED** — no backend exists, cannot be wired in this session

## Findings page
| ID | Element | Expected | Actual | Backend | Status |
|---|---|---|---|---|---|
| F.01 | Findings table load | Fetch /api/report, render rows | Works | GET /api/report | PASS |
| F.02 | Row click | Open slide-over | Works | none | PASS |
| F.03 | Validate button | POST /api/validate | Wired | POST /api/validate/<job>/<seq> | WIRED |
| F.04 | Retest button | POST /api/retest | Wired | POST /api/retest/<job>/<seq> | WIRED |
| F.05 | Sort headers | Reorder table | Works | none | PASS |
| F.06 | Density toggle | Change row density | Works | none | PASS |\n| F.10 | Severity/status filter chips | Filter actual findings and show live counts | Filters current finding set | Client-side loaded report data | WIRED |\n| F.11 | Export CSV | Download findings as CSV | Exports all loaded findings | Client-side loaded report data | WIRED |
| F.07 | Bulk mark verified | Bulk verification | Hidden | none | HIDDEN |
| F.08 | Bulk delete | Bulk delete | Hidden | none | HIDDEN |
| F.09 | AI banner | Dismiss/approve proposal | Hidden | none | HIDDEN |

## Run page
| R.01 | Catalog load | Fetch /api/tools | Works | GET /api/tools | PASS |
| R.02 | Run button | POST /api/run | Works | POST /api/run | PASS |
| R.03 | Cancel button | POST cancel | Works | POST /api/jobs/<id>/cancel | PASS |
| R.04 | SSE stream | Live output | Works | GET /api/jobs/<id>/stream | PASS |\n| R.05 | Out-of-scope response | Explain refusal and log blocked attempt without bypass | Actual target/tool shown; execution remains blocked | POST /api/scope/override | WIRED |

## Scope page
| S.01 | Scope list | Fetch /api/scope | Works | GET /api/scope | PASS |
| S.02 | Check scope | POST /api/scope/check | Works | POST /api/scope/check | PASS |
| S.03 | Import button | Import scope JSON | Hidden | none | HIDDEN |
| S.04 | + Add rule | Add scope rule | Hidden | none | HIDDEN |
| S.05 | Log blocked attempt | Record that an out-of-scope run was refused; never bypass scope | Live target/tool details; logging leaves execution blocked | POST /api/scope/override | WIRED |

## Report page
| P.01 | Generate Markdown | Download md report | Downloads | GET /api/report?format=md | WIRED |
| P.02 | Generate HTML | Download html report | Downloads | GET /api/report?format=html | WIRED |
| P.03 | Generate PDF | Download pdf report | Downloads | GET /api/report?format=pdf | WIRED |\n| P.06 | Engagement snapshot | Show current job/finding/verified counts | Derived from live report JSON | GET /api/report?format=json | WIRED |
| P.04 | Recent reports table | List generated reports | Removed from UI; no persisted report-history backend | none | HIDDEN |
| P.05 | Known Vulns preview | Show report-backed CVE data | Removed from UI; static sample rows were not trustworthy | none | HIDDEN |

## Retest page
| T.01 | Queue table | Show verified findings | Live queue | GET /api/report | WIRED |
| T.02 | Retest button (row) | POST /api/retest | Wired | POST /api/retest/<job>/<seq> | WIRED |

## Sessions page
| X.01 | Sessions list | Fetch /api/msf/sessions | Live list | GET /api/msf/sessions | WIRED |
| X.02 | Interact button | Expand command panel; POST explicit operator command; render returned output | Live sessions only; stored/closed sessions remain read-only | POST /api/msf/sessions/<id>/exec | WIRED |

## Attack Surface page
| A.01 | Graph render + node inspection | Fetch /api/pivot/graph; draw observed exploit/session/forward edges; click or keyboard-inspect nodes | Live graph and empty/error states; browser tests added | GET /api/pivot/graph | WIRED |

## Catalog page
| C.01 | Tool list | Fetch /api/tools | Live list | GET /api/tools | WIRED |
| C.02 | Adapter column | Show whether a registered adapter exists for each tool | Real boolean from adapter registry | GET /api/tools | WIRED |

## Threat Intel page
| I.01 | Search button | Run cve or lookup | Sidebar hidden until a web backend is available | none | HIDDEN |
| I.02 | CVE result card | Show CVE data | Static sample removed from active navigation | none | HIDDEN |

## Compliance page
| M.01 | Framework progress | Real compliance mapping | Hardcoded | none | HIDDEN |

## Settings page
| G.01 | Theme selector | Persist theme | Sidebar hidden pending persisted settings workflow | none | HIDDEN |
| G.02 | Members list | Show real users | Hardcoded | none | HIDDEN |

## Components page
| D.01 | Design system demo | Not user-facing | Static | none | HIDDEN |

## Cross-cutting
| B.01 | Notifications | Read notification list | Trigger hidden; static sample notifications are not active | none | HIDDEN |
| B.02 | Workspace switcher | Change workspace | Multi-workspace UI removed from active interaction; current engagement is shown from scope | none | HIDDEN |
| B.03 | Command palette | Search pages, tools, and loaded findings; navigate/open result | Live client-side search over current page data and catalog | GET /api/tools; GET /api/report?format=json | WIRED |
| B.04 | Help / shortcuts | Show kbd legend and execute documented shortcuts | Palette, page navigation, density, new job, close, and sidebar shortcuts are wired | none | WIRED |
| B.05 | Sidebar collapse | Toggle | Works | none | PASS |

## Pass 1 targets (this session)
- P.01, P.02, P.03 → wire to /api/report downloads
- T.01, T.02 → replace with real retest queue
- X.01 → wire to /api/msf/sessions
- C.01 → wire to /api/tools
- S.05 → wire to /api/scope/override
- F.09 → hide AI banner (no backend)
- F.07, F.08 → hide bulk bar buttons (no backend)
- B.03 → strip palette mock actions, keep search

## Pass 2 targets (next session)
- A.01 → wire to /api/pivot/graph
- I.01, I.02 → add CVE/lookup web routes, wire search

## Pass 3 targets
- M.01, G.01, G.02, D.01, B.01, B.02, S.03, S.04, P.04, P.05 → hide or mark "coming soon"
