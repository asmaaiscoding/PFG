# Access-Control Corpus Candidate Backlog

This is a research backlog only. Do not treat an entry as part of the measured
real corpus until its vulnerable ref is fetched, the affected endpoint ids are
confirmed by the extractor, and the manifest passes `pfg corpus-validate`.

## Django First

| Priority | Project | Advisory | Target subtype | Useful because | Expected difficulty |
| --- | --- | --- | --- | --- | --- |
| P0 | Sentry | CVE-2026-26004 / GHSL-2025-130 | `TENANT_ISOLATION_FAILURE` | Large, high-value app; cross-organization endpoint-level access bug in `GroupEventJsonView`; fixed by commit `45bc78fd57514a04eb62e73dd1eeb3ca2d723997`. | High |
| P0 | Plane | CVE-2026-30244 / GHSA-87x4-j8vh-p5qf | `MISSING_AUTH` | Clear DRF public workspace/member endpoints; good missing-auth case outside existing apps. | Medium |
| P0 | Weblate | CVE-2026-27457 / GHSA-wppc-7cq7-cgfv | `OBJECT_LEVEL_PERMISSION_BYPASS` or `TENANT_ISOLATION_FAILURE` | Queryset/object scoping failure in `AddonViewSet` and `/api/addons/`; fixed by commit `3f58f9a4152bc0cbdd6eff5954f9c7bc4d9f0af9`. | Medium |
| P0 | pretix | CVE-2025-14881 / GHSA-r2h2-g46h-8mx8 | `IDOR` | UUID/file access IDOR, useful beyond numeric `pk` examples; fixed by commit prefix `4b56518`. | Medium-high |
| P1 | Nautobot | CVE-2023-51649 / GHSA-vf5m-xrhm-v999 | `OBJECT_LEVEL_PERMISSION_BYPASS` | Reuses an existing project but adds missing object-level permission on Job Buttons. | Medium-high |
| P1 | wger | CVE-2026-40474 / GHSA-xppv-4jrx-qf8m | `MISSING_ROLE` | Clear vertical privilege escalation on `/config/gym-config/edit`; fixed by commit `47ee5af93b3ced24b9f94b0a8b9296b50bc9523f`. | Low-medium |
| P1 | wger | CVE-2026-27838 / GHSA-42cr-w2gr-m54q | `IDOR` | Cache-mediated IDOR; pushes PFG beyond direct ORM lookup patterns. | High |
| P2 | NetBox | GHSA-32w2-6gm2-7766 | `MISSING_AUTH` / `OBJECT_LEVEL_PERMISSION_BYPASS` | Popular Django app; global search permission bypass. No CVE assigned. | High |
| P2 | Zulip | CVE-2026-25741 / GHSA-vhhx-84f7-rc8j | `MISSING_ROLE` | Billing-role authorization case; good role-specific endpoint. | High |

## Spring Later

Hold these until the Django pipeline is stable and the Spring extractor can
model security filters, route matchers, and `@PreAuthorize` consistently.

| Candidate | Target subtype | Use |
| --- | --- | --- |
| Spring Security CVE-2022-31692 | `MISSING_AUTH` | Forward/include dispatcher authorization bypass. |
| Spring Boot CVE-2026-40976 / GHSA-8v8j-3hxp-93wr | `MISSING_AUTH` | Default web security ineffective. |
| Spring Security CVE-2026-22733 | `MISSING_AUTH` | Actuator CloudFoundry authorization bypass. |
| Spring Boot CVE-2025-22235 | `MISSING_ROLE` | `EndpointRequest.to()` matcher bypass. |
| Spring Framework CVE-2024-38827 | `MISSING_ROLE` | Case-sensitive authorization bypass. |

## Acceptance Criteria For Promotion

- Advisory URL, repository URL, vulnerable ref, and fixed ref/commit recorded.
- Endpoint/function names confirmed from the patch or advisory.
- Extracted endpoint ids match manifest labels.
- Labels are advisory-backed and access-control only.
- The app has its own `dataset_split_group`.
- `pfg corpus-validate benchmarks/realworld` remains OK.
