---
myst:
  html_meta:
    description: "Charmed OpenSearch Revision 366 release notes - GCS snapshot repositories, SMTP support, OpenSearch 2.19.6 upgrade, and single-kernel repository restructuring."
---

<!--
RELEASE NOTES — REVIEW NOTES (not published)

Sources and inferences:
- Repository: canonical/opensearch-operator (inferred from the open workspace; the local
  checkout is a fork on branch "release-notes-test", so the track branch 2/edge was used).
- Product: Charmed OpenSearch; track 2 (docs default version and repo default branch 2/edge).
- from-ref: rev315 (opensearch-operator) and rev60 (opensearch-dashboards-operator), taken
  from the newest release-notes file in this repo: docs/reference/release-notes/revision-315.md
  (December 16, 2025). Both confirmed ancestors of 2/edge. Ranges: rev315...2/edge (49 commits),
  rev60...2/edge (18 commits). to-ref: 2/edge HEAD (73177e1, tagged opensearch/rev366 on
  2026-09-14, so this release IS revision 366).
- Charmed OpenSearch Dashboards included as a component: detected in revision-315's notes,
  confirmed by the user in the previous run of this document (regenerated here after the
  old generated file was deleted on this branch).
- Workload version 2.19.6 from kubernetes/workload_version and machine/workload_version on 2/edge.

Auto-sort: RAN (user-enabled in the previous run of this release). Moves:
- PR #766: "feat: support GCS repository for snapshot operations" — Other improvements → Features (evidence: feat: prefix)
- PR #782: "feat: create buckets/containers if not available" — Other improvements → Features (evidence: feat: prefix)
- PR #781: "fix: handle the situation that opensearch_failover does not exist" — Other improvements → Bug fixes (evidence: fix: prefix, shipped behaviour)
- PR #799: "Bug-fix: removing the hard-coded unit value..." — Other improvements → Bug fixes (evidence: Bug-fix: prefix, shipped Terraform module behaviour)
- PR #797: "fix: add missing LIBID to notifications manager" — Other improvements → Bug fixes (evidence: fix: prefix, shipped charm libs)
- PR #804: "fix: set blocked status for invalid object-storage secrets" — Other improvements → Bug fixes (evidence: fix: prefix, shipped behaviour)
- PR #815: "Fix/temporary file service account gcs" — Other improvements → Bug fixes (evidence: fix verb, shipped GCS behaviour)
Carried a fix signal but deliberately left in Other improvements (infrastructure-only targets):
- PR #672: "Fix manual upgrades tests for large deployments" (tests)
- PR #806: "Fix charm Build" (build)
- PR #812: "fix: Fix spread installation" (spread test infra)
- PR #854: "fix: Fix tutorial test" (test infra)
Neutral prefixes (patch:/docs:/chore:) left in place unflagged per auto-sort rules.
Dashboards component: 0 entries moved (all docs:/patch: prefixed or docs-only).
Known auto-sort misses left in Other improvements (no conventional-commit prefix):
- PR #789 "add smtp support" and PR #786 "add rollback compatibility" read as features but
  carry no feat: prefix — review manually whether to move them to Features.

Spelling corrections applied to PR titles (typos, meaning untouched):
- PR #799: "acomodating" → "accommodating", "exclusivness" → "exclusiveness".

TODOs for the release owner:
- Confirm the final published charm revision numbers before publishing: opensearch/rev366
  is tagged at 2/edge HEAD (this release); the latest dashboards tag is
  opensearch-dashboards/rev78, 2 commits behind 2/edge HEAD, so this release ships a new,
  not-yet-tagged dashboards revision (expected rev79).
- Fill in the snap revisions in the Compatibility table once the 2.19.6 snaps are published
  to the 2/stable channel (as of writing, 2/stable still serves 2.19.4: opensearch rev 98,
  opensearch-dashboards rev 54; 2/edge serves 2.19.6: opensearch amd64 rev 261,
  dashboards amd64 rev 155).
- Add the OCI rock/image artifacts for the two K8s charm rows (marked TODO in the table).
- Verify the opensearch/rev365 and opensearch/rev366 tag pairing (assumed to be the
  architecture/base pair from the same release run) and which revision ships on which
  architecture.
- Verify all artifacts and links are up to date before publishing.
- Add this release to docs/reference/release-notes/index.md (Releases list; the toctree
  entry for revision-366 is already present).

Note on tag namespaces: since the single-kernel restructuring (PR #830), tags are namespaced
(opensearch/revNNN, opensearch-k8s/revN, opensearch-dashboards/revNN,
opensearch-dashboards-k8s/revN). The flat revNNN tags (latest rev349) are stale
pre-restructuring tags and must not be used to determine the current revision.
-->

(reference-release-notes-revision-366)=
# Revision 366

September 15, 2026

This release of Charmed OpenSearch upgrades OpenSearch and OpenSearch Dashboards to version 2.19.6 and adds support for Google Cloud Storage (GCS) repositories for snapshot operations, including automatic creation of buckets and containers when they are not available. It also introduces SMTP support and rollback compatibility for safer downgrades.

The charm repositories were restructured into a single kernel, grouping the Kubernetes and VM charms of both OpenSearch and OpenSearch Dashboards into single repositories, and the documentation was thoroughly revamped with a new structure, a new homepage, and consolidated Dashboards content.

[Charmhub](https://charmhub.io/opensearch) | [Deploy guide](how-to-deploy-standard) | [Upgrade instructions](how-to-minor-upgrade) | [System requirements](reference-system-requirements)

## Charmed OpenSearch

The Charmed OpenSearch charm includes the following changes:

### Features

This release adds the following new features:

* feat: support GCS repository for snapshot operations ([PR \#766](https://github.com/canonical/opensearch-operator/pull/766))  
* feat: create buckets/containers if not available ([PR \#782](https://github.com/canonical/opensearch-operator/pull/782))  

### Bug fixes

The following bugs have been fixed:

* fix: handle the situation that opensearch_failover does not exist ([PR \#781](https://github.com/canonical/opensearch-operator/pull/781))  
* Bug-fix: removing the hard-coded unit value + accommodating for the mutual exclusiveness of units and machines variables ([PR \#799](https://github.com/canonical/opensearch-operator/pull/799))  
* fix: add missing LIBID to notifications manager ([PR \#797](https://github.com/canonical/opensearch-operator/pull/797))  
* fix: set blocked status for invalid object-storage secrets ([PR \#804](https://github.com/canonical/opensearch-operator/pull/804))  
* Fix/temporary file service account GCS ([PR \#815](https://github.com/canonical/opensearch-operator/pull/815))  

### Other improvements

The following further improvements are included:

* Release notes for new release ([PR \#761](https://github.com/canonical/opensearch-operator/pull/761))  
* Pin Terraform Version ([PR \#778](https://github.com/canonical/opensearch-operator/pull/778))  
* chore: update rust toolchain ([PR \#784](https://github.com/canonical/opensearch-operator/pull/784))  
* docs: Home page remodeling ([PR \#785](https://github.com/canonical/opensearch-operator/pull/785))  
* [[DPE-7579](https://warthogs.atlassian.net/browse/DPE-7579)] Fix manual upgrades tests for large deployments ([PR \#672](https://github.com/canonical/opensearch-operator/pull/672))  
* [Docs] Fix the 404 error page ([PR \#787](https://github.com/canonical/opensearch-operator/pull/787))  
* docs: add Dashboards documentation link to the Nav Menu ([PR \#776](https://github.com/canonical/opensearch-operator/pull/776))  
* docs: Implement rediraffe redirects ([PR \#788](https://github.com/canonical/opensearch-operator/pull/788))  
* [[DPE-9144](https://warthogs.atlassian.net/browse/DPE-9144)] add smtp support ([PR \#789](https://github.com/canonical/opensearch-operator/pull/789))  
* docs: Add GA and cookie consent ([PR \#791](https://github.com/canonical/opensearch-operator/pull/791))  
* docs: Add autogenerated metadata description ([PR \#793](https://github.com/canonical/opensearch-operator/pull/793))  
* chore: add LIBID, LIBPATCH to notifications ([PR \#795](https://github.com/canonical/opensearch-operator/pull/795))  
* [[DPE-9280](https://warthogs.atlassian.net/browse/DPE-9280)] docs: Restructure documentation content ([PR \#790](https://github.com/canonical/opensearch-operator/pull/790))  
* docs: Update the cookie banner ([PR \#801](https://github.com/canonical/opensearch-operator/pull/801))  
* [[DPE-4727](https://warthogs.atlassian.net/browse/DPE-4727)] docs: Add Dashboards mentions ([PR \#798](https://github.com/canonical/opensearch-operator/pull/798))  
* Fix charm Build ([PR \#806](https://github.com/canonical/opensearch-operator/pull/806))  
* Re-enable charmcraft build cache ([PR \#807](https://github.com/canonical/opensearch-operator/pull/807))  
* [[DPE-9332](https://warthogs.atlassian.net/browse/DPE-9332)] docs: Add Dashboard docs content as a submodule ([PR \#803](https://github.com/canonical/opensearch-operator/pull/803))  
* [[DPE-9411](https://warthogs.atlassian.net/browse/DPE-9411)] docs: Structure updates ([PR \#808](https://github.com/canonical/opensearch-operator/pull/808))  
* fix: Fix spread installation ([PR \#812](https://github.com/canonical/opensearch-operator/pull/812))  
* [[DPE-9412](https://warthogs.atlassian.net/browse/DPE-9412)] docs: Us spelling update ([PR \#810](https://github.com/canonical/opensearch-operator/pull/810))  
* [[DPE-9022](https://warthogs.atlassian.net/browse/DPE-9022)] Add rollback docs ([PR \#743](https://github.com/canonical/opensearch-operator/pull/743))  
* [[DPE-9134](https://warthogs.atlassian.net/browse/DPE-9134)] add rollback compatibility ([PR \#786](https://github.com/canonical/opensearch-operator/pull/786))  
* patch: Remove unit tests, integration tests(except `test_charm.py`) and remove charm code leaving only `charm.py` ([PR \#818](https://github.com/canonical/opensearch-operator/pull/818))  
* patch: Bump opensearch-charms-single-kernel to v0.0.5 ([PR \#819](https://github.com/canonical/opensearch-operator/pull/819))  
* docs: Homepage upgrade ([PR \#823](https://github.com/canonical/opensearch-operator/pull/823))  
* docs: Finalise Url migration ([PR \#826](https://github.com/canonical/opensearch-operator/pull/826))  
* docs: Upgrade Sphinx Stack ([PR \#829](https://github.com/canonical/opensearch-operator/pull/829))  
* docs: Add tutorial test ([PR \#824](https://github.com/canonical/opensearch-operator/pull/824))  
* [[DPE-10677](https://warthogs.atlassian.net/browse/DPE-10677)] patch: Grouping the kubernetes charm and VM charm in single repo ([PR \#830](https://github.com/canonical/opensearch-operator/pull/830))  
* patch: Remove tag job from release workflows ([PR \#834](https://github.com/canonical/opensearch-operator/pull/834))  
* patch: Fix tag in `metadata.yaml` ([PR \#836](https://github.com/canonical/opensearch-operator/pull/836))  
* chore: Update OpenSearch Dashboards docs submodule ([PR \#838](https://github.com/canonical/opensearch-operator/pull/838))  
* patch: Bump opensearch-charms-single-kernel to v0.0.9 ([PR \#839](https://github.com/canonical/opensearch-operator/pull/839))  
* [[DPE-10534](https://warthogs.atlassian.net/browse/DPE-10534)] patch: Bump opensearch-charms-single-kernel to v0.0.10 ([PR \#841](https://github.com/canonical/opensearch-operator/pull/841))  
* [[DPE-10850](https://warthogs.atlassian.net/browse/DPE-10850)][[DPE-10867](https://warthogs.atlassian.net/browse/DPE-10867)] patch: Bump opensearch-charms-single-kernel to v0.0.12 ([PR \#845](https://github.com/canonical/opensearch-operator/pull/845))  
* patch: Fix charmcraft revision ([PR \#848](https://github.com/canonical/opensearch-operator/pull/848))  
* [[DPE-10428](https://warthogs.atlassian.net/browse/DPE-10428)] docs: Documentation revamp ([PR \#827](https://github.com/canonical/opensearch-operator/pull/827))  
* chore: Update OpenSearch Dashboards docs submodule ([PR \#849](https://github.com/canonical/opensearch-operator/pull/849))  
* [[DPE-11035](https://warthogs.atlassian.net/browse/DPE-11035)][[DPE-11026](https://warthogs.atlassian.net/browse/DPE-11026)][[DPE-10922](https://warthogs.atlassian.net/browse/DPE-10922)][[DPE-10876](https://warthogs.atlassian.net/browse/DPE-10876)] patch: Bump opensearch-charms-single-kernel to v0.0.13 ([PR \#851](https://github.com/canonical/opensearch-operator/pull/851))  
* fix: Fix tutorial test ([PR \#854](https://github.com/canonical/opensearch-operator/pull/854))  
* patch: Bump opensearch-charms-single-kernel to v0.0.14 ([PR \#855](https://github.com/canonical/opensearch-operator/pull/855))  

## Charmed OpenSearch Dashboards

The Charmed OpenSearch Dashboards charm includes the following changes:

### Other improvements

The following improvements are included:

* Documentation content migrated and published to RTD ([PR \#225](https://github.com/canonical/opensearch-dashboards-operator/pull/225))  
* docs: Update the Dashboards docs to fit into OpenSearch docs better ([PR \#234](https://github.com/canonical/opensearch-dashboards-operator/pull/234))  
* docs: Fix spell check errors in READMEs ([PR \#237](https://github.com/canonical/opensearch-dashboards-operator/pull/237))  
* docs: update `README.md` ([PR \#239](https://github.com/canonical/opensearch-dashboards-operator/pull/239))  
* [[DPE-9414](https://warthogs.atlassian.net/browse/DPE-9414)] docs: Build submodule automation ([PR \#241](https://github.com/canonical/opensearch-dashboards-operator/pull/241))  
* patch: fix spread installation ([PR \#246](https://github.com/canonical/opensearch-dashboards-operator/pull/246))  
* docs: Test pr automation ([PR \#250](https://github.com/canonical/opensearch-dashboards-operator/pull/250))  
* docs: Fix dashboards docs update workflow ([PR \#252](https://github.com/canonical/opensearch-dashboards-operator/pull/252))  
* [[DPE-9763](https://warthogs.atlassian.net/browse/DPE-9763)] patch: Migrate to single kernel ([PR \#253](https://github.com/canonical/opensearch-dashboards-operator/pull/253))  
* patch: Bump opensearch-dashboards-charms-single-kernel to v0.0.6 ([PR \#266](https://github.com/canonical/opensearch-dashboards-operator/pull/266))  
* Update rust in `charmcraft.yaml` ([PR \#268](https://github.com/canonical/opensearch-dashboards-operator/pull/268))  
* docs: Documentation content revamp ([PR \#273](https://github.com/canonical/opensearch-dashboards-operator/pull/273))  
* [[DPE-10681](https://warthogs.atlassian.net/browse/DPE-10681)] patch: Merge dashboards k8s in dashboards-operator ([PR \#275](https://github.com/canonical/opensearch-dashboards-operator/pull/275))  
* [[DPE-10681](https://warthogs.atlassian.net/browse/DPE-10681)] patch: Fix release ([PR \#278](https://github.com/canonical/opensearch-dashboards-operator/pull/278))  
* docs: Fix a link ([PR \#276](https://github.com/canonical/opensearch-dashboards-operator/pull/276))  
* patch: Bump opensearch-dashboards-charms-single-kernel to v0.0.10 ([PR \#281](https://github.com/canonical/opensearch-dashboards-operator/pull/281))  
* docs: Minor updates and fixes migration from docs revamp ([PR \#282](https://github.com/canonical/opensearch-dashboards-operator/pull/282))  
* patch: Bump opensearch-dashboards-charms-single-kernel to v0.0.11 ([PR \#283](https://github.com/canonical/opensearch-dashboards-operator/pull/283))  

## Compatibility

The following table lists the compatible versions and artifacts for this release:

| Charm                             | Revision                                                                      | Hardware architecture | OpenSearch version                                                              | Minimum Juju version | Artifacts                                                       |
| :-------------------------------- | :---------------------------------------------------------------------------- | :-------------------- | :------------------------------------------------------------------------------ | :------------------- | :--------------------------------------------------------------- |
| Charmed OpenSearch                | [366](https://github.com/canonical/opensearch-operator/tree/opensearch/rev366) | AMD64                 | [v2.19.6](https://github.com/opensearch-project/OpenSearch/releases/tag/2.19.6) | 3.5+                 | Snap: [revision 261](https://snapcraft.io/opensearch)           |
| Charmed OpenSearch K8s            | [16](https://github.com/canonical/opensearch-operator/tree/opensearch-k8s/rev16) | AMD64                 | [v2.19.6](https://github.com/opensearch-project/OpenSearch/releases/tag/2.19.6) | 3.5+                 | TODO                                                             |
| Charmed OpenSearch Dashboards     | [79](https://github.com/canonical/opensearch-dashboards-operator/tree/opensearch-dashboards/rev79) | AMD64                 | [v2.19.6](https://github.com/opensearch-project/OpenSearch/releases/tag/2.19.6) | 3.5+                 | Snap: [revision 155](https://snapcraft.io/opensearch-dashboards) |
| Charmed OpenSearch Dashboards K8s | [5](https://github.com/canonical/opensearch-dashboards-operator/tree/opensearch-dashboards-k8s/rev5) | AMD64                 | [v2.19.6](https://github.com/opensearch-project/OpenSearch/releases/tag/2.19.6) | 3.5+                 | TODO                                                             |