---
myst:
  html_meta:
    description: "Software testing guide for Charmed OpenSearch covering unit tests, integration tests, and performance benchmarking procedures."
---

(explanation-software-testing)=
# Software testing for charms

```{note}
All commands are written for `juju >= v.3.1`.
Charmed OpenSearch no longer supports `juju v.2`.
```

Most types of standard [software tests](https://en.wikipedia.org/wiki/Software_testing)
are applicable to Charmed OpenSearch.

```{note}
The charm logic lives in the
[`opensearch-single-kernel-library`](https://github.com/canonical/opensearch-single-kernel-library),
which contains the full unit and integration test suites. The charm
repositories only carry minimal smoke-level integration tests that validate
the charm wiring. Unless stated otherwise, run the tests described below in
the library repository.
```

## Unit test

The unit tests live in the
[`opensearch-single-kernel-library`](https://github.com/canonical/opensearch-single-kernel-library)
repository. Clone it and run:

```bash
tox run -e unit
```

## Integration test

The integration test coverage is rather rich in the OpenSearch charm. Most
of it lives in the
[`opensearch-single-kernel-library`](https://github.com/canonical/opensearch-single-kernel-library)
repository (`tox run -e integration` there); the charm repository itself
carries a minimal smoke-level suite — see the
[Contributing](contributing-guide)
guide for how to run it.

For high availability (HA) related tests, each test serves as an integration as well as a smoke test
with continuous writes routine being perpetually ran in parallel of whatever operation the test is involved in.
These continuous writes ensure the availability of the service under different conditions.

HA tests make use of one of the 2 fixtures:

- `c_writes_runner`: creates an index with a default replication factor
  and continuously "bulk" feeds data to it
- `c_balanced_writes_runner`: creates an index with 2 primary shards and as many replica shards
  as the number of nodes available in the cluster,  and continuously "bulk" feeds data to it.

After each test completes, the index gets deleted.

## Performance test

Refer to the [OpenSearch VM benchmark](how-to-perform-load-testing)
guide for charmed OpenSearch.
