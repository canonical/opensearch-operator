[note]All commands are written for `juju v.3.1.7 +`[/note]

# How to configure Azure storage 

This guide will teach you how to deploy and configure the [Azure Integrator charm](https://charmhub.io/azure-storage-integrator) for [Azure](https://azure.com/), send the configurations to the Charmed OpenSearch application, and update it.

---

## Configure Azure integrator

First, deploy and run the [`azure-integrator`](https://charmhub.io/azure-storage-integrator) charm:

```shell
juju deploy azure-storage-integrator --channel latest/edge
juju config azure-storage-integrator storage-account=<Azure_storage_account> container=<Azure_storage_container>
```

Then, add the the secret key to the charm:

```shell
juju add-secret mysecret secret-key=<Azure_storage_key>
juju grant-secret mysecret azure-storage-integrator
juju config azure-storage-integrator credentials=<secret-id>
```

>See all other configuration parameters in the [Configuration section](https://charmhub.io/azure-storage-integrator/configuration)  of the azure-integrator documentation.

## Integrate with Charmed OpenSearch

To pass these configurations to Charmed OpenSearch, integrate the two applications:

```shell
juju integrate azure-storage-integrator opensearch
```