## Deploy Charmed OpenSearch

To deploy Charmed OpenSearch, all you need to do is run the following command, which will fetch the charm from [Charmhub](https://charmhub.io/opensearch?channel=edge) and deploy it to your model:

```bash
juju deploy opensearch --channel=edge
```

Juju will now fetch Charmed OpenSearch and begin deploying it to the LXD cloud. This process can take several minutes depending on your machine. You can track the progress by running:

```bash
juju status --watch=1s
```

This command is useful for checking the status of your Juju Model, including the applications and machines that it hosts. Some of the helpful information it displays include IP addresses, ports, state, etc. The output of this command updates once per second. When the application is ready, `juju status` will show:

```bash
Model     Controller         Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo    localhost/localhost  2.9.37   unsupported  11:24:30Z

App         Version  Status   Scale  Charm       Channel   Rev  Exposed  Message
opensearch           blocked      1  opensearch  dpe/edge   96  no       Waiting for TLS to be fully configured...

Unit           Workload  Agent  Machine  Public address  Ports      Message
opensearch/0*  blocked   idle   0        10.23.62.156    27017/tcp  Waiting for TLS to be fully configured...

Machine  State    Address       Inst id        Series  AZ  Message
0        started  10.23.62.156  juju-d35d30-0  focal       Running
```

To exit the screen with `juju status --watch 1s`, enter `Ctrl+c`.

The status message `Waiting for TLS to be fully configured...` exists because Charmed OpenSearch requires TLS to be configured before use, to ensure data is transmitted securely. If you're seeing a status message like the following, [you need to set the correct kernel parameters to continue](#setting-kernel-parameters).

```bash
vm.swappiness should be 0 - net.ipv4.tcp_retries2 should be 5
```
