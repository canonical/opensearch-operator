# `opensearch_client`

## Usage

This relation interface describes the expected behaviour of any charm interfacing with the [Charmed Opensearch Operator](https://github.com/canonical/opensearch-operator) using the `opensearch-client` relation.

In most cases, this will be accomplished using the [data_interfaces library](https://github.com/canonical/data-platform-libs/blob/main/lib/charms/data_platform_libs/v0/data_interfaces.py), although charm developers are free to provide alternative libraries as long as they fulfil the behavioural and schematic requirements described in this document.

## Direction

```mermaid
flowchart TD
    Requirer -- database, \nextra-user-roles --> Provider
    Provider -- username, \npassword, \nhosts --> Requirer
```

As with all Juju relations, the `opensearch-client` interface consists of two parties: a Provider (opensearch charm), and a Requirer (application charm). The Requirer will be expected to provide an index name, and the Provider will provide new unique credentials (along with other optional fields), which can be used to access the index itself.

## Behavior

Both the Requirer and the Provider need to adhere to criteria to be considered compatible with the interface.

### Provider
- Is expected to create an application user inside the opensearch cluster when the requirer provides the `index` field.
- Is expected to provide `username` and `password` fields when Requirer provides the `index` field.
- Is expected to provide the `hosts` field containing all cluster host addresses in a comma-separated list.
- Is expected to provide the `version` field describing the installed version of opensearch.

### Requirer

- Is expected to provide an index name in the `index` field.
- Is expected to provide identical values in the `index` field if several requirer units provide it in the relation.
- Is expected to have unique credentials for each relation. Therefore, different instances of the same Charm (juju applications) will have different relations with different credentials.
- Is expected to have different relations names on Requirer with the same interface name if Requirer needs access to multiple database charms.
- Is expected to allow multiple different Juju applications to access the same database name.
- Is expected to add any `extra-user-roles` provided by the Requirer to the created user (e.g. `extra-user-roles=admin`).
  - This can be set to two values:
    - default: this has read-write permissions over the index that has been generated for this relation.
    - admin: this has control over the index, including how cluster roles are assigned to nodes in the cluster.

## Relation Data

### Provider

[\[JSON Schema\]](./schemas/provider.json)

Provider provides credentials, host addresses, TLS info and database-specific fields. It should be placed in the **application** databag.


#### Example
```yaml
  relation-info:
  - endpoint: opensearch-client
    related-endpoint: opensearch-app-consumer
    application-data:
      index: myindex
      hosts: 10.180.162.200:9200,10.180.162.75:9200
      password: Dy0k2UTfyNt2B13cfe412K7YGs07S4U7
      username: opensearch-client_4_user
```

### Requirer

[\[JSON Schema\]](./schemas/requirer.json)

Requirer provides index name. This should be placed in the **unit** databag in at least one unit of the Requirer.

#### Example

```yaml
  relation-info:
  - endpoint: opensearch-app-consumer
    related-endpoint: opensearch-client
    application-data: {}
    related-units:
      worker-a/0:
        in-scope: true
        data:
          index: myindex
```
