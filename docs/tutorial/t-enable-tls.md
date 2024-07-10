> [Charmed OpenSearch Tutorial](/t/9722) >  3. Enable TLS encryption

# Enable encryption with TLS

[Transport Layer Security (TLS)](https://en.wikipedia.org/wiki/Transport_Layer_Security) is a protocol used to encrypt data exchanged between two applications. Essentially, it secures data transmitted over a network.

Typically, enabling TLS internally within a highly available database or between a highly available database and client/server applications requires a high level of expertise. This has all been encoded into Charmed OpenSearch so that configuring TLS requires minimal effort on your end.

TLS is enabled by integrating Charmed OpenSearch with the [Self Signed Certificates Charm](https://charmhub.io/self-signed-certificates). This charm centralises TLS certificate management consistently and handles operations like providing, requesting, and renewing TLS certificates.

In this section, you will learn how to enable security in your OpenSearch deployment using TLS encryption.

[note type="caution"]
**[Self-signed certificates](https://en.wikipedia.org/wiki/Self-signed_certificate) are not recommended for a production environment.**

Check [this guide](/t/11664) for an overview of the TLS certificates charms available. 
[/note]

---

## Configure TLS

Before enabling TLS on Charmed OpenSearch we must first deploy the `self-signed-certificates` charm:

```shell
juju deploy self-signed-certificates --config ca-common-name="Tutorial CA"
```

Wait until `self-signed-certificates` is active. Use `juju status --watch 1s` to monitor the progress.

<!-- TODO: juju status output-->

## Integrate with OpenSearch

To enable TLS on Charmed OpenSearch, you must integrate (also known as "relate") the two applications. We will go over integrations in more detail in the [next page](/t/9714) of this tutorial.

To integrate `self-signed-certificates` with `opensearch`, run the following command:

```shell
juju integrate self-signed-certificates opensearch
```

The OpenSearch service will start. You can see the new integrations with `juju status --relations`.

<!-- TODO: juju status output-->

> **Next step:** [4. Integrate with a client application](/t/9714)