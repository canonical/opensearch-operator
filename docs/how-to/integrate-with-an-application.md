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
from charms.data_platform.libs.interfaces.opensearch_client import OpenSearchRequires

class MyCharm(CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.opensearch = OpenSearchRequires(self, "opensearch", "my_index")
        self.framework.observe(self.opensearch.on.index_created, self._on_index_created)

    def _on_index_created(self, event):
        # Handle the index_created event
        pass
```

The `OpenSearchRequires` class accepts:

* `charm` — the charm instance
* `relation_name` — must match the name in `metadata.yaml`
* `index` — the index name to connect to
* `extra_user_roles` (optional) — additional roles for the user
* `additional_secret_fields` (optional) — extra secret fields to share

### Create the integration

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

## Rotate passwords

### Rotate a client password

Remove and re-add the relation to generate a new user with a new password:

```shell
juju remove-relation opensearch <application>
juju integrate opensearch <application>
```

### Rotate the admin password

To set a specific password:

```shell
juju run opensearch/leader set-password password=<new-password>
```

To generate a random password:

```shell
juju run opensearch/leader set-password
```

To retrieve the current password:

```shell
juju run opensearch/leader get-password
```
