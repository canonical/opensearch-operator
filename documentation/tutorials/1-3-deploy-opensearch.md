## Deploy Charmed OpenSearch

To deploy Charmed OpenSearch, all you need to do is run the following command, which will fetch the charm from [Charmhub](https://charmhub.io/opensearch?channel=edge) and deploy it to your model:

```bash
juju deploy opensearch --channel=edge
```

Juju will now fetch Charmed OpenSearch and begin deploying it to the LXD cloud. This process can take several minutes depending on your machine. You can track the progress by running:

```bash
watch -c juju status --color
```

This command is useful for checking the status of your Juju Model, including the applications and machines that it hosts. Some of the helpful information it displays include IP addresses, ports, state, etc. The output of this command updates once every other second. When the application is ready, `juju status` will show:

```bash
Model     Controller       Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo  localhost/localhost  2.9.42   unsupported  15:12:41Z

App         Version  Status   Scale  Charm       Channel  Rev  Exposed  Message
opensearch           blocked      1  opensearch  edge      22  no       Waiting for TLS to be fully configured...

Unit           Workload  Agent  Machine  Public address  Ports  Message
opensearch/0*  blocked   idle   0        10.180.162.97          Waiting for TLS to be fully configured...

Machine  State    Address        Inst id        Series  AZ  Message
0        started  10.180.162.97  juju-3305a8-0  jammy       Running


```

To exit the screen with `watch -c juju status --color`, enter `Ctrl+c`.

The status message `Waiting for TLS to be fully configured...` exists because Charmed OpenSearch requires TLS to be configured before use, to ensure data is encrypted in transit for the HTTP and Transport layers. If you're seeing a status message like the following, [you need to set the correct kernel parameters to continue](./1-2-setup-environment.md).

```bash
vm.swappiness should be 0 - net.ipv4.tcp_retries2 should be 5
```

---

## Next Steps

The next stage in this tutorial is about enabling TLS on the OpenSearch charm. This step is essential for the charm's function, and the tutorial can be found [here](./1-4-enable-tls.md).
