(reference-release-notes-revision-315)=
# Revision 315

December 16, 2025

This release of the OpenSearch Operator adds support for Ubuntu 24.04 (Noble Numbat), upgrades OpenSearch and OpenSearch Dashboards version to 2.19.4, and introduces significant features including OAuth and JWT authentication, and full Terraform support.

[Charmhub](https://charmhub.io/opensearch) | [Deploy guide](https://canonical-charmed-opensearch.readthedocs-hosted.com/2/how-to/deploy/deploy-on-lxd/) | [Upgrade instructions](https://canonical-charmed-opensearch.readthedocs-hosted.com/2/how-to/upgrade/perform-a-minor-upgrade/) | [System requirements](https://canonical-charmed-opensearch.readthedocs-hosted.com/2/reference/system-requirements/) 

## Charmed OpenSearch

### Features

* [[DPE-6091](https://warthogs.atlassian.net/browse/DPE-6091)] Add OAuth integration ([PR \#612](https://github.com/canonical/opensearch-operator/pull/612))  
* [[DPE-8017](https://warthogs.atlassian.net/browse/DPE-8017)] Add JWT authentication ([PR \#696](https://github.com/canonical/opensearch-operator/pull/696))
* [[DPE-6534](https://warthogs.atlassian.net/browse/DPE-6534)] Add Terraform charm and product modules for simple & large deployments ([PR \#545](https://github.com/canonical/opensearch-operator/pull/545))
* [[DPE-4115](https://warthogs.atlassian.net/browse/DPE-4115)] Add OpenSearch Performance Profiles ([PR \#466](https://github.com/canonical/opensearch-operator/pull/466))
* Upgrade OpenSearch to 2.19.4 ([PR \#745](https://github.com/canonical/opensearch-operator/pull/745))
* Migrate the documentation to ReadTheDocs ([PR \#708](https://github.com/canonical/opensearch-operator/pull/708))
  
### Bug fixes 

* [[DPE-7996](https://warthogs.atlassian.net/browse/DPE-7996)] Fix OpenSearchStartTimeoutError being raised all the time ([PR \#686](https://github.com/canonical/opensearch-operator/pull/686))
* [[DPE-8408](https://warthogs.atlassian.net/browse/DPE-8408)] Isolate OpenSearchNotFullyReadyError and add retry mechanism ([PR \#704](https://github.com/canonical/opensearch-operator/pull/704))
* [[DPE-7828](https://warthogs.atlassian.net/browse/DPE-7828)] Fix main orchestrator demotion ([PR \#689](https://github.com/canonical/opensearch-operator/pull/689))
* [[DPE-6877](https://warthogs.atlassian.net/browse/DPE-6877)] Fix failover bootstrapping cluster ([PR \#629](https://github.com/canonical/opensearch-operator/pull/629))
* [[DPE-6869](https://warthogs.atlassian.net/browse/DPE-6869)] Fix starting up after scale down to 0 ([PR \#635](https://github.com/canonical/opensearch-operator/pull/635))
* [[DPE-7559](https://warthogs.atlassian.net/browse/DPE-7559)] Fix leader-elected hook for non-leader units ([PR \#661](https://github.com/canonical/opensearch-operator/pull/661))
* [[DPE-6422](https://warthogs.atlassian.net/browse/DPE-6422)] Fix upgrade path with snap rev. 65 ([PR \#553](https://github.com/canonical/opensearch-operator/pull/553))
* [[DPE-7076](https://warthogs.atlassian.net/browse/DPE-7076)] Data node fails to start ([PR \#671](https://github.com/canonical/opensearch-operator/pull/671))
* [[DPE-7545](https://warthogs.atlassian.net/browse/DPE-7545)] Fix s3-uri-style handling ([PR \#654](https://github.com/canonical/opensearch-operator/pull/654))
* [[DPE-5460](https://warthogs.atlassian.net/browse/DPE-5460)] Restart data only nodes without lock ([PR \#460](https://github.com/canonical/opensearch-operator/pull/460))
* [[DPE-5671](https://warthogs.atlassian.net/browse/DPE-5671)] Logic change in how check if CA rotation in complete in cluster ([PR \#486](https://github.com/canonical/opensearch-operator/pull/486))
* Only data node ignores lock if restarting ([PR \#762](https://github.com/canonical/opensearch-operator/pull/762))
* Fixing Terraform Flaky Tests due to Limited storage on github runners ([PR \#765](https://github.com/canonical/opensearch-operator/pull/765))
* Fix CA rotation edge case on small deployments ([PR \#767](https://github.com/canonical/opensearch-operator/pull/767))
* Set blocked message on verify repository fail ([PR \#769](https://github.com/canonical/opensearch-operator/pull/769))
* Clear missing relations ([PR \#763](https://github.com/canonical/opensearch-operator/pull/763))
* Remove verify repository from requirer error checks ([PR \#772](https://github.com/canonical/opensearch-operator/pull/772))

### Other improvements 

* [[DPE-5830](https://warthogs.atlassian.net/browse/DPE-5830)] Bump to Ubuntu 24.04 ([PR \#495](https://github.com/canonical/opensearch-operator/pull/495))
* [[DPE-6598](https://warthogs.atlassian.net/browse/DPE-6598)] Move to OpenSearch v2.18 ([PR \#563](https://github.com/canonical/opensearch-operator/pull/563))
* [[DPE-4196](https://warthogs.atlassian.net/browse/DPE-4196)] Plugin Management Refactor ([PR \#435](https://github.com/canonical/opensearch-operator/pull/435))
* [[DPE-6922](https://warthogs.atlassian.net/browse/DPE-6922)] Integrate TiCS ([PR \#605](https://github.com/canonical/opensearch-operator/pull/605))
* [[DPE-6285](https://warthogs.atlassian.net/browse/DPE-6285)] Update poetry to v2 ([PR \#527](https://github.com/canonical/opensearch-operator/pull/527))
* [[DPE-5444](https://warthogs.atlassian.net/browse/DPE-5444)] Bump to ops 2.19 ([PR \#575](https://github.com/canonical/opensearch-operator/pull/575))
* [[DPE-7560](https://warthogs.atlassian.net/browse/DPE-7560)] Remove wrong default base path for snapshots repositories ([PR \#658](https://github.com/canonical/opensearch-operator/pull/658))
* [[DPE-6878](https://warthogs.atlassian.net/browse/DPE-6878)] Stabilize upgrade tests ([PR \#626](https://github.com/canonical/opensearch-operator/pull/626))
* [[DPE-6787](https://warthogs.atlassian.net/browse/DPE-6787)] Add smoke test ([PR \#588](https://github.com/canonical/opensearch-operator/pull/588))
* [[DPE-5667](https://warthogs.atlassian.net/browse/DPE-5667)] Move away from ops\_test's wait\_for\_idle to wait\_until ([PR \#479](https://github.com/canonical/opensearch-operator/pull/479))
* Replace Discourse docs with a charm description on Charmhub ([PR \#760](https://github.com/canonical/opensearch-operator/pull/760))
* Refactor code and verify repository after all units save credentials ([PR \#774](https://github.com/canonical/opensearch-operator/pull/774))
* Rework Plugins ([PR \#775](https://github.com/canonical/opensearch-operator/pull/775))
* Rework Snapshots ([PR \#718](https://github.com/canonical/opensearch-operator/pull/718))

## Charmed OpenSearch Dashboards

### Features

* [[DPE-5867](https://warthogs.atlassian.net/browse/DPE-5867)] Add terraform module  ([PR \#134](https://github.com/canonical/opensearch-dashboards-operator/pull/134))
* [[DPE-6091](https://warthogs.atlassian.net/browse/DPE-6091)] Add oauth integration ([PR \#180](https://github.com/canonical/opensearch-dashboards-operator/pull/180))
* [[DPE-6936](https://warthogs.atlassian.net/browse/DPE-6936)] Update to 2.19.1 ([PR \#182](https://github.com/canonical/opensearch-dashboards-operator/pull/182))
* [[DPE-8018](https://warthogs.atlassian.net/browse/DPE-8018)] Add JWT authentication ([PR \#217](https://github.com/canonical/opensearch-dashboards-operator/pull/217))
* [[DPE-5832](https://warthogs.atlassian.net/browse/DPE-5832)][[DPE-6252](https://warthogs.atlassian.net/browse/DPE-6252)] Add 24.04 support ([PR \#138](https://github.com/canonical/opensearch-dashboards-operator/pull/138))
* Add new Prometheus Rules using the python exporter ([PR \#159](https://github.com/canonical/opensearch-dashboards-operator/pull/159))
* Bump version to 2.19.2 ([PR \#198](https://github.com/canonical/opensearch-dashboards-operator/pull/198))
* Release 2.19.4 ([PR \#224](https://github.com/canonical/opensearch-dashboards-operator/pull/224))

### Bug fixes 

* [[DPE-7774](https://warthogs.atlassian.net/browse/DPE-7774)] Raise if error on install ([PR \#214](https://github.com/canonical/opensearch-dashboards-operator/pull/214))
* [[DPE-7002](https://warthogs.atlassian.net/browse/DPE-7002)] Update opensearch health checks ([PR \#215](https://github.com/canonical/opensearch-dashboards-operator/pull/215))
* [[DPE-7928](https://warthogs.atlassian.net/browse/DPE-7928)] Block if we fail to get the provider info from the oauth relation ([PR \#218](https://github.com/canonical/opensearch-dashboards-operator/pull/218))
* [[DPE-6600](https://warthogs.atlassian.net/browse/DPE-6600)] Move away from `libjuju` and `add_machine` ([PR \#167](https://github.com/canonical/opensearch-dashboards-operator/pull/167))
* [[DPE-6598](https://warthogs.atlassian.net/browse/DPE-6598)][[DPE-6786](https://warthogs.atlassian.net/browse/DPE-6786)] Update to 2.18 and fix CI ([PR \#169](https://github.com/canonical/opensearch-dashboards-operator/pull/169))
* [[DPE-5699](https://warthogs.atlassian.net/browse/DPE-5699)] Update CI workflow versions, add juju 3.6, and remove build wrapper ([PR \#124](https://github.com/canonical/opensearch-dashboards-operator/pull/124))
* Fix branch release on CI ([PR \#123](https://github.com/canonical/opensearch-dashboards-operator/pull/123))
* Remove dependency breaking ccc-hub ([PR \#136](https://github.com/canonical/opensearch-dashboards-operator/pull/136))
* Rollback Cache use ([PR \#139](https://github.com/canonical/opensearch-dashboards-operator/pull/139))

### Other improvements 

* [[DPE-6922](https://warthogs.atlassian.net/browse/DPE-6922)] Integrate TiCS ([PR \#176](https://github.com/canonical/opensearch-dashboards-operator/pull/176))
* [[DPE-4307](https://warthogs.atlassian.net/browse/DPE-4307)] HA process interrupt tests ([PR \#114](https://github.com/canonical/opensearch-dashboards-operator/pull/114))
* [[DPE-6876](https://warthogs.atlassian.net/browse/DPE-6876)] Migration to spread ([PR \#178](https://github.com/canonical/opensearch-dashboards-operator/pull/178))
* [[DPE-6217](https://warthogs.atlassian.net/browse/DPE-6217)] Remove channel + revision mentions ([PR \#145](https://github.com/canonical/opensearch-dashboards-operator/pull/145))
* [[DPE-6536](https://warthogs.atlassian.net/browse/DPE-6536)] Improve terraform charm module ([PR \#164](https://github.com/canonical/opensearch-dashboards-operator/pull/164))
* [[DPE-6687](https://warthogs.atlassian.net/browse/DPE-6687)][[DPE-6690](https://warthogs.atlassian.net/browse/DPE-6690)][[DPE-6691](https://warthogs.atlassian.net/browse/DPE-6691)] Extend TF charm modules ([PR \#168](https://github.com/canonical/opensearch-dashboards-operator/pull/168))
* [[DPE-6858](https://warthogs.atlassian.net/browse/DPE-6858)] Add expose support in Terraform([PR \#173](https://github.com/canonical/opensearch-dashboards-operator/pull/173))
* [[DPE-5704](https://warthogs.atlassian.net/browse/DPE-5704)] Update COS to use jammy series ([PR \#125](https://github.com/canonical/opensearch-dashboards-operator/pull/125))
* Add alert if an OpenSearch Dashboards scrape fails ([PR \#140](https://github.com/canonical/opensearch-dashboards-operator/pull/140))
* Add `promtool` check and test in the CI ([PR \#142](https://github.com/canonical/opensearch-dashboards-operator/pull/142))
* Both `ci.yaml` and `test_prometheus_rules.yaml` were using same lock ([PR \#146](https://github.com/canonical/opensearch-dashboards-operator/pull/146))
* Migrate to charmcraft 3 poetry plugin ([PR \#148](https://github.com/canonical/opensearch-dashboards-operator/pull/148))
* Finish charmcraft 3 migration ([PR \#150](https://github.com/canonical/opensearch-dashboards-operator/pull/150))
* Switch charmcraft to latest/candidate ([PR \#151](https://github.com/canonical/opensearch-dashboards-operator/pull/151))
* Use single (cached) build for tests & release ([PR \#155](https://github.com/canonical/opensearch-dashboards-operator/pull/155))
* Remove unused dependencies from main and charm-libs groups ([PR \#156](https://github.com/canonical/opensearch-dashboards-operator/pull/156))
* Use stage instead of prime in charmcraft files part ([PR \#158](https://github.com/canonical/opensearch-dashboards-operator/pull/158))
* Switch to charmcraft stable ([PR \#162](https://github.com/canonical/opensearch-dashboards-operator/pull/162))
* Add revision to the grafana dashboard title ([PR \#163](https://github.com/canonical/opensearch-dashboards-operator/pull/163))
* Update tls channel ([PR \#170](https://github.com/canonical/opensearch-dashboards-operator/pull/170))
* Update tls lib ([PR \#127](https://github.com/canonical/opensearch-dashboards-operator/pull/127))
* Add config profile=testing ([PR \#128](https://github.com/canonical/opensearch-dashboards-operator/pull/128))
* Remove get-password ([PR \#130](https://github.com/canonical/opensearch-dashboards-operator/pull/130))


## Compatibility 

| Charm                         | Revision                                                                     | Hardware architecture | OpenSearch version                                                              | Minimum Juju version | Artifacts                                                       |
| :---------------------------- | :--------------------------------------------------------------------------- | :-------------------- | :------------------------------------------------------------------------------ | :------------------- | --------------------------------------------------------------- |
| Charmed OpenSearch            | [315](https://github.com/canonical/opensearch-operator/tree/rev315)          | AMD64                 | [v2.19.4](https://github.com/opensearch-project/OpenSearch/releases/tag/2.19.4) | 3.5+                 | Snap: [revision 98](https://snapcraft.io/opensearch)            |
| Charmed OpenSearch Dashboards | [60](https://github.com/canonical/opensearch-dashboards-operator/tree/rev60) | AMD64                 | [v2.19.4](https://github.com/opensearch-project/OpenSearch/releases/tag/2.19.4) | 3.5+                 | Snap: [revision 54](https://snapcraft.io/opensearch-dashboards) |