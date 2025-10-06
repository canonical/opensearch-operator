(tutorial-2-deploy-opensearch)=
# 2. Deploy OpenSearch

> [Charmed OpenSearch Tutorial](tutorial-index) >  2. Deploy OpenSearch

Charmed OpenSearch supports performance profile.
It is recommended in a single host deployment with LXD to use the `testing` profile,
which will only consume 1G RAM per container.

To deploy Charmed OpenSearch, run the following command:

```shell
juju deploy opensearch -n 3
```

```{note}
The `-n` flag is optional and specifies the number of units to deploy.
In this case, we are deploying three units of Charmed OpenSearch.
We recommend deploying at least three units for high availability.
```

This command will fetch the charm from
[Charmhub](https://charmhub.io/opensearch?channel=beta) and deploy 3 units to the LXD cloud.
This process can take several minutes depending on your machine.

You can track the progress by running:

```shell
juju status --watch 1s
```

```{note}
This command is useful for checking the status of your Juju model,
including the applications and machines it hosts.
Helpful information it displays includes IP addresses, ports, state, etc.
The output of this command updates once every other second.
```

When the application is ready, `juju status` will show something similar to the sample output below:

```shell
Model     Controller       Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo  localhost/localhost  3.5.3    unsupported  12:36:56Z

App         Version  Status   Scale  Charm       Channel  Rev  Exposed  Message
opensearch           blocked      3  opensearch  2/stable   168  no       Missing TLS relation with this cluster.

Unit           Workload  Agent      Machine  Public address  Ports  Message
opensearch/0*  blocked   idle       0        10.95.38.94            Missing TLS relation with this cluster.
opensearch/1   blocked   executing  1        10.95.38.139           Missing TLS relation with this cluster.
opensearch/2   blocked   idle       2        10.95.38.212           Missing TLS relation with this cluster.

Machine  State    Address       Inst id        Base          AZ  Message
0        started  10.95.38.94   juju-be3883-0  ubuntu@22.04      Running
1        started  10.95.38.139  juju-be3883-1  ubuntu@22.04      Running
2        started  10.95.38.212  juju-be3883-2  ubuntu@22.04      Running
```

To exit the `juju status` screen, enter `Ctrl + C`.

The status message `Waiting for TLS to be fully configured...` is displayed because
Charmed OpenSearch requires TLS to be configured before use, to ensure data is encrypted in transit
for the HTTP and Transport layers. We will do this in the next step.

If you see the following status message:

```shell
vm.swappiness should be 0 - net.ipv4.tcp_retries2 should be 5
```

you need to [set the correct kernel parameters](tutorial-1-set-up-the-environment) to continue.

```{note}
**Next step:** [3. Enable TLS](tutorial-3-enable-encryption)
```
