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
