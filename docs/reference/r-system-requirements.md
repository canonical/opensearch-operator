# System requirements

The following are the minimum software and hardware requirements to run Charmed OpenSearch on VM.

## Software

* Ubuntu 22.04 LTS (Jammy) or later
* Juju `v.3.1.7+` 

## Hardware

Make sure your machine meets the following requirements:

* 16 GB of RAM.
* 4 CPU cores.
* At least 20 GB of available storage

The charm is based on the [charmed-opensearch snap](https://snapcraft.io/opensearch). It currently supports the following architectures:
* `amd64`

[note]
**Note**: We highly recommend using solid-state drives (SSDs) installed on the host for node storage where possible in order to avoid performance issues in your cluster because of latency or limited throughput.
[/note]

## Networking

* Access to the internet is required for downloading required snaps and charms
* Certain network ports must be open for internal communication: See the OpenSearch documentation for [Network requirements](https://opensearch.org/docs/2.6/install-and-configure/install-opensearch/index/#network-requirements).