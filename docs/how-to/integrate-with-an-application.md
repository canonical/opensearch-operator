---
myst:
  html_meta:
    description: "Integrate client applications with Charmed OpenSearch using the opensearch_client interface or data-integrator charm."
---

(how-to-integrate-with-an-application)=
# How to integrate with an application

This guide shows how to connect applications to Charmed OpenSearch, either through
a Juju charm integration or via the `data-integrator` charm for non-Juju applications.

## Integrate a Juju charm with OpenSearch

If you are developing a charm that needs to connect to OpenSearch, use the `opensearch_client` interface.

### Define the interface

In your charm's `metadata.yaml`:

```yaml
requires:
  opensearch:
    interface: opensearch_client
```

### Implement the interface in your charm

Fetch the library:

```shell
charmcraft fetch-lib charms.data_platform_libs.v0.data_interfaces
```

In your `charm.py`:

```python
from charms.data_platform_libs.v0.data_interfaces import OpenSearchRequires

class MyCharm(CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.opensearch = OpenSearchRequires(self, "opensearch", "my_index")
        self.framework.observe(self.opensearch.on.index_created, self._on_index_created)

    def _on_index_created(self, event):
        # Handle the index_created event
        pass
```

The `OpenSearchRequires` constructor accepts:

* `charm` — the charm instance
* `relation_name` — must match the name in `metadata.yaml`
* `index` — the index name to connect to
* `extra_user_roles` (optional) — additional roles for the user
* `additional_secret_fields` (optional) — extra secret fields to share

See the [`OpenSearchRequires` class](https://github.com/canonical/data-platform-libs/blob/main/lib/charms/data_platform_libs/v0/data_interfaces.py)
in the `data_interfaces` library source for the full list of optional parameters.

### Create the integration

Connect OpenSearch to your application:

```shell
juju integrate opensearch <application>
```

To remove:

```shell
juju remove-relation opensearch <application>
```

## Integrate a non-Juju application with OpenSearch

Use the [`data-integrator`](https://charmhub.io/data-integrator) charm to provide
credentials and connection details to applications outside the Juju ecosystem.

Deploy it:

```shell
juju deploy data-integrator --config index-name=<index-name>
```

Integrate with OpenSearch:

```shell
juju integrate data-integrator opensearch
```

The charm will be `blocked` until the integration is established.

To remove the integration:

```shell
juju remove-relation data-integrator opensearch
```

### Retrieve the credentials

Once the integration is established, retrieve the connection credentials (username, password,
endpoints, and CA certificate) by running the `get-credentials` action:

```shell
juju run data-integrator/leader get-credentials
```

<details>

<summary>Output example</summary>

```yaml
opensearch:
  endpoints: 10.95.38.139:9200,10.95.38.212:9200,10.95.38.94:9200
  index: test-index
  password: j3JWFnDkoumCxn0CtKZRCmdRMUlYTZFI
  tls-ca: |-
    -----BEGIN CERTIFICATE-----
    -----END CERTIFICATE-----
    -----BEGIN CERTIFICATE-----
    -----END CERTIFICATE-----
  username: opensearch-client_5
  version: 2.14.0
```

</details>

Use these credentials to connect your application to OpenSearch. For an example of connecting
with `curl`, see the [Tutorial](tutorial-4-integrate-with-a-client-application).

## Next steps

* [Manage passwords](how-to-manage-passwords) to rotate the credentials issued to the client.
* [Enable monitoring (COS)](how-to-monitoring) to observe the integrated workload.
* [Manage TLS encryption](how-to-enable-tls-encryption) to secure client-to-node traffic.
