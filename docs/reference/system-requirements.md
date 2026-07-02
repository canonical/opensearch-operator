---
myst:
  html_meta:
    description: "Minimum software and hardware requirements for deploying Charmed OpenSearch including Ubuntu, Juju, LXD, and storage specifications."
---

(reference-system-requirements)=
# System requirements

Charmed OpenSearch is built to operate on Ubuntu together with Juju.
It is generally recommended to use the latest LTS of both, as these are the versions prioritized
in the charm’s software tests.

By default, OpenSearch is memory and disk-intensive, but the requirements for running
Charmed OpenSearch depend heavily on your use-case.
This page outlines the minimum requirements to deploy Charmed OpenSearch successfully.

## Software

* Ubuntu 22.04 LTS (Jammy) or later
* Juju `v.3.5.3+`
  * Older minor versions of Juju 3 may be compatible, but are not officially supported.
* LXD `6.1+`

## Hardware

* 16 GB of RAM.
* 4 CPU cores.
* At least 20 GB of available storage
* `amd64` architecture

```{note}
We highly recommend using solid-state drives (SSDs) installed on the host for node storage
where possible in order to avoid performance issues in your cluster because of latency
or limited throughput.
```

```{note}
See also: [How to perform load testing](how-to-perform-load-testing).
```

## Networking

* Internet access is required for downloading artifacts from the snap and charm stores
* Certain network ports must be open for internal communication:
  See the OpenSearch documentation for
  [Network requirements](https://opensearch.org/docs/2.6/install-and-configure/install-opensearch/index/#network-requirements).

## Kernel parameters

OpenSearch requires specific kernel parameters to be set on the host machine and propagated
to every container or VM where OpenSearch runs. These settings are enforced by both the
`testing` and `production` profiles.

See [Performance profiles](explanation-performance-profiles) for details on how profiles
use these parameters.

| Parameter | Required value | Purpose |
| :--- | :--- | :--- |
| `vm.swappiness` | `0` | Disables swap to prevent OpenSearch from being swapped to disk, which causes severe performance degradation. |
| `vm.max_map_count` | `262144` | Required by OpenSearch for mmap-based file access to index segments. |
| `net.ipv4.tcp_retries2` | `5` | Prevents long network timeouts from blocking cluster operations. |
| `fs.file-max` | `1048576` | Ensures sufficient file descriptors for large deployments with many shards and indices. |

For instructions on how to apply these settings on the host and propagate them to
containers, see [How to deploy on LXD](how-to-deploy-lxd).
