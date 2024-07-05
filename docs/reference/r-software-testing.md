# Charm Testing reference

> **:information_source: Hint**: Use [Juju 3](/t/5064). (Charmed OpenSearch dropped support for juju 2.9)

There are [a lot of test types](https://en.wikipedia.org/wiki/Software_testing) available and most of them are well applicable for Charmed OpenSearch. Here is a list prepared by Canonical:

* Unit tests
* Integration tests
* Performance tests

## Unit tests:
Please check the "[Contributing](https://github.com/canonical/opensearch-operator/blob/main/CONTRIBUTING.md#testing)" guide and follow `tox run -e unit` examples there.

## Integration tests:
The integration tests coverage is rather rich in the OpenSearch charm. 
Please check the "[Contributing](https://github.com/canonical/opensearch-operator/blob/main/CONTRIBUTING.md#testing)" guide and follow `tox run -e integration` examples there.

For HA related tests - each test serves as an integration as well as a smoke test with continuous writes routine being perpetually ran in parallel of whatever operation the test is involved in. 
These continuous writes ensure the availability of the service under different conditions. 

HA tests make use of one of the 2 fixtures:
-  `c_writes_runnner`: creates an index with a default replication factor and continuously "bulk" feeds data to it 
- `c_balanced_writes_runner`: creates an index with 2 primary shards and as many replica shards as the number of nodes available in the cluster,  and continuously "bulk" feeds data to it.

After each test completes, the index gets deleted. 

## Performance tests:
Refer to the [OpenSearch VM benchmark](https://discourse.charmhub.io/t/load-testing-for-charmed-opensearch/13987) guide for charmed OpenSearch.