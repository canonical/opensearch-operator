## Transport Layer Security (TLS)

[TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) is used to encrypt data exchanged between two applications; it secures data transmitted over the network. Typically, enabling TLS within a highly available database, and between a highly available database and client/server applications, requires domain-specific knowledge and a high level of expertise. Fortunately, the domain-specific knowledge has been encoded into Charmed OpenSearch. This means enabling TLS on Charmed Opensearch is easily available and requires minimal effort on your end.

TLS is mandatory for OpenSearch deployments because nodes in an OpenSearch cluster require TLS to communicate with each other securely. Therefore, the OpenSearch charm will be in a blocked state until TLS is configured. Since TLS certificates are already being prepared for internal communication between OpenSearch nodes, we make use of the same certificate for external communications with the REST API. Therefore, TLS must be configured before connecting to the charm.

TLS is enabled via relations, by relating Charmed OpenSearch to the [TLS Certificates Charm](https://charmhub.io/tls-certificates-operator). The TLS Certificates Charm centralises TLS certificate management in a consistent manner and handles providing, requesting, and renewing TLS certificates.

### Configure TLS

Before enabling TLS on Charmed OpenSearch we must first deploy the `tls-certificates-operator` charm:

```bash
juju deploy tls-certificates-operator
```

Wait until the `tls-certificates-operator` is ready to be configured. When it is ready to be configured `watch -c juju status --color` will show:

```bash
Model     Controller       Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo  localhost/localhost  2.9.42   unsupported  15:16:43Z

App                        Version  Status   Scale  Charm                      Channel  Rev  Exposed  Message
opensearch                          blocked      1  opensearch                 edge      22  no       Waiting for TLS to be fully configured...
tls-certificates-operator           blocked      1  tls-certificates-operator  stable    22  no       Configuration options missing: ['certificate', 'ca-certificate']

Unit                          Workload  Agent  Machine  Public address  Ports  Message
opensearch/0*                 blocked   idle   0        10.180.162.97          Waiting for TLS to be fully configured...
tls-certificates-operator/0*  blocked   idle   1        10.180.162.44          Configuration options missing: ['certificate', 'ca-certificate']

Machine  State    Address        Inst id        Series  AZ  Message
0        started  10.180.162.97  juju-3305a8-0  jammy       Running
1        started  10.180.162.44  juju-3305a8-1  jammy       Running
```

Now we can configure the TLS certificates. Configure the  `tls-certificates-operator` to use self signed certificates:

```bash
juju config tls-certificates-operator generate-self-signed-certificates="true" ca-common-name="Tutorial CA"
```

*Note: this tutorial uses [self-signed certificates](https://en.wikipedia.org/wiki/Self-signed_certificate); self-signed certificates should not be used in a production cluster. To set the correct certificates, see the [TLS operator documentation](https://github.com/canonical/tls-certificates-operator).*

### Enable TLS

After configuring the certificates `juju status` will show the status of `tls-certificates-operator` as active. To enable TLS on Charmed OpenSearch, relate the two applications:

```bash
juju relate tls-certificates-operator opensearch
```

The OpenSearch service will start, and the output of `juju status --relations` should now resemble the following:

```bash
Model     Controller       Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo  localhost/localhost  2.9.42   unsupported  15:24:18Z

App                        Version  Status  Scale  Charm                      Channel  Rev  Exposed  Message
opensearch                          active      1  opensearch                 edge      22  no
tls-certificates-operator           active      1  tls-certificates-operator  stable    22  no

Unit                          Workload  Agent  Machine  Public address  Ports  Message
opensearch/0*                 active    idle   0        10.180.162.97
tls-certificates-operator/0*  active    idle   1        10.180.162.44

Machine  State    Address        Inst id        Series  AZ  Message
0        started  10.180.162.97  juju-3305a8-0  jammy       Running
1        started  10.180.162.44  juju-3305a8-1  jammy       Running

Relation provider                       Requirer                            Interface                 Type     Message
opensearch:opensearch-peers             opensearch:opensearch-peers         opensearch_peers          peer
opensearch:service                      opensearch:service                  rolling_op                peer
tls-certificates-operator:certificates  opensearch:certificates             tls-certificates          regular
tls-certificates-operator:replicas      tls-certificates-operator:replicas  tls-certificates-replica  peer
```

---

## Next Steps

The next stage in this tutorial is about connecting to and using the OpenSearch charm, and can be found [here](/t/charmed-opensearch-tutorial-connecting-to-opensearch/9714).
