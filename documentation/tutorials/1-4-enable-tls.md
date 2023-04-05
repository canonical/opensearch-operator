## Transport Layer Security (TLS)

[TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) is used to encrypt data exchanged between two applications; it secures data transmitted over the network. Typically, enabling TLS within a highly available database, and between a highly available database and client/server applications, requires domain-specific knowledge and a high level of expertise. Fortunately, the domain-specific knowledge has been encoded into Charmed OpenSearch. This means enabling TLS on Charmed Opensearch is easily available and requires minimal effort on your end.

TLS is enabled via relations, by relating Charmed OpenSearch to the [TLS Certificates Charm](https://charmhub.io/tls-certificates-operator). The TLS Certificates Charm centralises TLS certificate management in a consistent manner and handles providing, requesting, and renewing TLS certificates.

### Configure TLS

Before enabling TLS on Charmed OpenSearch we must first deploy the `TLS-certificates-operator` charm:

```bash
juju deploy tls-certificates-operator
```

Wait until the `tls-certificates-operator` is ready to be configured. When it is ready to be configured `watch -c juju status --color` will show:

```bash
Model     Controller         Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo    localhost/localhost  2.9.37   unsupported  09:24:12Z

App                        Version  Status   Scale  Charm                      Channel  Rev  Exposed  Message
opensearch                          blocked      1  opensearch                 edge      11  no       Waiting for TLS to be fully configured...
tls-certificates-operator           blocked      1  tls-certificates-operator  beta      22  no       Configuration options missing: ['certificate', 'ca-certificate']

Unit                          Workload  Agent  Machine  Public address  Ports  Message
opensearch/0*                 blocked   idle   0        10.137.5.232           Waiting for TLS to be fully configured...
tls-certificates-operator/0*  blocked   idle   1        10.137.5.33            Configuration options missing: ['certificate', 'ca-certificate']

Machine  State    Address       Inst id        Series  AZ  Message
0        started  10.137.5.232  juju-2f4c88-0  jammy       Running
1        started  10.137.5.33   juju-2f4c88-1  jammy       Running
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

The OpenSearch service will start and the output of `juju status` should now resemble the following:

```bash
Model     Controller         Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo    localhost/localhost  2.9.37   unsupported  09:24:12Z

App                        Version  Status  Scale  Charm                      Channel  Rev  Exposed  Message
opensearch                          active      1  opensearch                 edge      11  no
tls-certificates-operator           active      1  tls-certificates-operator  stable      22  no

Unit                          Workload  Agent  Machine  Public address  Ports  Message
opensearch/0*                 active    idle   0        10.137.5.232
tls-certificates-operator/0*  active    idle   1        10.137.5.33

Machine  State    Address       Inst id        Series  AZ  Message
0        started  10.137.5.232  juju-2f4c88-0  jammy       Running
1        started  10.137.5.33   juju-2f4c88-1  jammy       Running
```

---

## Next Steps

The next stage in this tutorial is about connecting to and using the OpenSearch charm, and can be found [here](./tutorial-connecting-to-opensearch.md).
