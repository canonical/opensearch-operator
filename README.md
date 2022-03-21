# OpenSearch Operator

## Description :pencil:

The OpenSearch Operator provides a easy way of deploying a highly scalable, reliable and secure OpenSearch cluster with an out of the box :gift: experience.

[OpenSearch](https://opensearch.org/)  is a community-driven, open source search and analytics engine for all types of data, including textual, numerical, geospatial, structured, and unstructured. It's suited for a broad of use cases like real-time application monitoring, log analytics, and website search.


## Usage :crystal_ball:

### Self-signed certificates :lock_with_ink_pen:

You can easily generate your certificates following these steps:

1. Clone this repo, get inside of it and be sure to have [openssl](https://www.openssl.org/) on your machine and create a new template file named `openssl.conf` that has the following fields:
```
[req]
distinguished_name = dn
default_keyfile    = {{ node_name }}.csr
prompt             = no

[dn]
CN={{ node_name }}
OU="Data Platform"
O="Canonical"
L="TORONTO"
ST="ONTARIO"
C="CA"
```
**Note**: You can edit `CN`, `OU`, `O`, `L`, `ST` and `CA` fields.

2. Edit the `bin/helpers/admin.conf` and `bin/helpers/root.conf` if you wish to change `[dn]` fields.

3. Run the the following command:
```shell
./bin/helpers/root_admin_certs.sh
```

This will generate the `admin-key.pem`, `admin.pem`, `root-ca-key.pem`, `root-ca.pem` that will be used as juju resources.

4. Deploy it:
```shell
juju deploy opensearch \
    --resource tls_ca=./root-ca.pem \
    --resource tls_key=./root-ca-key.pem \
    --resource admin_key=admin-key.pem \
    --resource admin_cert=./admin.pem \
    --resource open_ssl_conf=./openssl.conf
```

For more information about self-signed certificates, please check the [OpenSearch documentation](https://opensearch.org/docs/latest/security-plugin/configuration/generate-certificates/).


### Relating with a Certificate Authority charms (EasyRSA, Vault and etc) :cop:

Not supported yet.

## Relations

Currently supported [relations](https://juju.is/docs/olm/relations) are:

* **Client**: pass the cluster name and port over the `elasticsearch` interface

## Contributing


Please see the [Juju SDK docs](https://juju.is/docs/sdk) for guidelines on enhancements to this
charm following best practice guidelines, and
[CONTRIBUTING.md](https://github.com/canonical/opensearch-operator/blob/main/CONTRIBUTING.md) for developer
guidance.

## License
The Charmed OpenSearch Operator is free software, distributed under the Apache Software License, version 2.0. See [LICENSE](https://github.com/canonical/opensearch-operator/blob/main/LICENSE) for more information.
