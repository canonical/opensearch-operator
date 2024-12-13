# How to integrate OpenSearch with an application

[Integrations](https://juju.is/docs/juju/relation) (formerly "relations") are connections between two applications with compatible endpoints. These connections simplify creating and managing users, passwords, and other shared data.

This guide will walk you through integrating your charm with OpenSearch via the `opensearch_client` interface or the `data-integrator` charm.

## Summary
<!-- TBD depending on whether there is a difference for large deployments, i.e. integrating with the orchestrator -->
  - [Integrate a different charm with OpenSearch](#integrate-a-different-charm-with-opensearch)
    - [Add the `opensearch_client` interface to your charm](#add-the-opensearch_client-interface-to-your-charm)
    - [Import the database interface libraries and define database event handlers](#import-the-database-interface-libraries-and-define-database-event-handlers)
    - [Integrate the client application with OpenSearch](#integrate-the-client-application-with-opensearch)
  - [Integrate an application outside of juju with OpenSearch](#integrate-an-application-outside-of-juju-with-opensearch)
    - [Deploy the `data-integrator` charm](#deploy-the-data-integrator-charm)
    - [Relate the `data-integrator` charm to an OpenSearch cluster](#relate-the-data-integrator-charm-to-an-opensearch-cluster)
    - [Remove the client integration](#remove-the-client-integration)
  - [Rotate the client password](#rotate-the-client-password)
    - [Rotate the `admin` password in the OpenSearch cluster](#rotate-the-admin-password-in-the-opensearch-cluster)

---

## Integrate a different charm with OpenSearch
The Charmed OpenSearch provides the `opensearch_client` interface to allow other charms to connect to it. This interface manages users, passwords, and other shared data. 

### Add the `opensearch_client` interface to your charm

To integrate your client application you must define the `opensearch_client` interface in your charm's `metadata.yaml` file.

```yaml
requires:
  opensearch:
    interface: opensearch_client
```

### Import the database interface libraries and define database event handlers

To integrate with the `opensearch_client` interface, import the database interface libraries and define the database event handlers in your charm's `charm.py` file.

First, navigate to your charm directory and fetch the [`data_interfaces`](https://charmhub.io/data-platform-libs/libraries/data_interfaces) charm library from Charmhub:

```bash
charmcraft fetch-lib charms.data_platform_libs.v0.data_interfaces
```

Next, import the `OpenSearchRequires` class from the `data_interfaces` library in your `charm.py` file:

```python
from charms.data_platform.libs.interfaces.opensearch_client import OpenSearchRequires
```

Then, instantiate the `OpenSearchRequires` class in your charm. The class takes the following parameters:
- `charm`: The charm instance
- `relation_name`: The name of the relation to which to connect. This should match the name of the relation defined in the `metadata.yaml` file (`opensearch` in the example above).
- `index`: The name of the index the client application will connect to.
- `extra_user_roles`: A string containing the additional roles to assign to the user. This is optional and defualts to `None`.
- `addional_secret_fields`: A list of additional secret fields to be shared with the client application. This is optional and defaults to an empty list.

```python
class MyCharm(CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.opensearch = OpenSearchRequires(self, "opensearch", "my_index")
```

Finally, define a callback function to handle the `index_created` event. This function will be called when the index is created in the OpenSearch cluster.

```python
class MyCharm(CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.opensearch = OpenSearchRequires(self, "opensearch", "my_index")
        self.framework.observe(self.opensearch.on.index_created, self._on_index_created)

    def _on_index_created(self, event):
        # Handle the index_created event
        pass
```

### Integrate the client application with OpenSearch
To integrate `opensearch` with your client applicationm run:

```shell
juju integrate opensearch <application>
```

To remove the integration, run:

```shell
juju remove-relation opensearch <application>
```

## Integrate an application outside of juju with OpenSearch

The `data-integrator` charm is a bare-bones charm that allows for central management of database users, providing support for different kinds of data platform products (e.g. MongoDB, MySQL, PostgreSQL, Kafka, etc) with a consistent, opinionated and robust user experience.

### Deploy the `data-integrator` charm

To deploy the `data-integrator` charm, run:

```shell
juju deploy data-integrator --config index-name=<index-name>
```

### Relate the `data-integrator` charm to an OpenSearch cluster
Once the `data-integrator` charm is deployed it will `blocked` until it is related to an OpenSearch cluster. To relate the `data-integrator` charm to an OpenSearch cluster, run:

```shell
juju integrate data-integrator opensearch
```

### Remove the client integration
To remove the integration (also known as "relation") between the `data-integrator` charm and the OpenSearch cluster, run:

```shell
juju remove-relation data-integrator opensearch
```

## Rotate the client password
To rotate the client password, remove the relation between the client application and the OpenSearch cluster and then re-add the relation. This will generate a user with a new password.

```shell
juju remove-relation opensearch <application>
juju integrate opensearch <application>
```

### Rotate the `admin` password in the OpenSearch cluster
To rotate the `admin` password in the OpenSearch cluster, run the following:

```shell
juju run opensearch/leader set-password password=<new-password>
```

A random password will be generated if you do not specify a password.

```shell
juju run opensearch/leader set-password
```

To get the password, run:

```shell
juju run opensearch/leader get-password
```