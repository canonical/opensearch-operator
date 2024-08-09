[note]
**Note**: All commands are written for `juju >= v.3.1`. Charmed OpenSearch no longer supports `juju v.2`.
[/note]

# Software testing for charms

Most types of standard [software tests](https://en.wikipedia.org/wiki/Software_testing) are applicable to Charmed OpenSearch.

This reference addresses the following types:
* [Unit test](#unit-test)
* [Integration test](#integration-test)
* [Performance test](#performance-test)

## Unit test
Check the [Contributing](https://github.com/canonical/opensearch-operator/blob/main/CONTRIBUTING.md#testing) guide and follow `tox run -e unit` examples there.

## Integration test
The integration tests coverage is rather rich in the OpenSearch charm. Check the [Contributing](https://github.com/canonical/opensearch-operator/blob/main/CONTRIBUTING.md#testing) guide and follow `tox run -e integration` examples there.

For high availability (HA) related tests, each test serves as an integration as well as a smoke test with continuous writes routine being perpetually ran in parallel of whatever operation the test is involved in. 
These continuous writes ensure the availability of the service under different conditions. 

HA tests make use of one of the 2 fixtures:
-  `c_writes_runnner`: creates an index with a default replication factor and continuously "bulk" feeds data to it 
- `c_balanced_writes_runner`: creates an index with 2 primary shards and as many replica shards as the number of nodes available in the cluster,  and continuously "bulk" feeds data to it.

After each test completes, the index gets deleted. 

## Performance test
Refer to the [OpenSearch VM benchmark](https://discourse.charmhub.io/t/load-testing-for-charmed-opensearch/13987) guide for charmed OpenSearch.