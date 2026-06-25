---
myst:
  html_meta:
    description: "Set up Azure Storage for Charmed OpenSearch backups using the Azure Storage Integrator charm and configure integration."
---

(how-to-back-up-configure-azure-storage)=
# How to configure Azure storage

This guide shows how to configure the
[Azure Storage Integrator charm](https://charmhub.io/azure-storage-integrator)
for OpenSearch backups.

## Deploy and configure the integrator

Deploy the charm and set storage account details:

```shell
juju deploy azure-storage-integrator --channel latest/edge
juju config azure-storage-integrator \
    storage-account=<storage-account> \
    container=<container-name>
```

Provide the storage key via a Juju secret:

```shell
juju add-secret azure-secret secret-key=<storage-key>
juju grant-secret azure-secret azure-storage-integrator
juju config azure-storage-integrator credentials=<secret-id>
```

See the [azure-storage-integrator configuration reference](https://charmhub.io/azure-storage-integrator/configuration)
for all available options.

## Integrate with Charmed OpenSearch

Connect the integrator to OpenSearch:

```shell
juju integrate azure-storage-integrator opensearch
```
