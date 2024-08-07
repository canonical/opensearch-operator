> [Charmed OpenSearch Tutorial](/t/9722) >  2. Deploy OpenSearch

# Deploy OpenSearch

To deploy Charmed OpenSearch, all you need to do is run the following command:

```shell
juju deploy opensearch --channel 2/edge
```

This will fetch the charm from [Charmhub](https://charmhub.io/opensearch?channel=edge) and begin deploying it to the LXD cloud. This process can take several minutes depending on your machine. 

You can track the progress by running:

```shell
juju status --watch 1s
```

>This command is useful for checking the status of your Juju model, including the applications and machines that it hosts. Some of the helpful information it displays include IP addresses, ports, state, etc. The output of this command updates once every other second. 

When the application is ready, `juju status` will show something similar to the sample output below: 

```shell
Model     Controller       Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo  localhost/localhost  2.9.42   unsupported  15:12:41Z

App         Version  Status   Scale  Charm       Channel  Rev  Exposed  Message
opensearch           blocked      1  opensearch  edge      22  no       Waiting for TLS to be fully configured...

Unit           Workload  Agent  Machine  Public address  Ports  Message
opensearch/0*  blocked   idle   0        10.180.162.97          Waiting for TLS to be fully configured...

Machine  State    Address        Inst id        Series  AZ  Message
0        started  10.180.162.97  juju-3305a8-0  jammy       Running
```

To exit the `juju status` screen, enter `Ctrl + C`.

The status message `Waiting for TLS to be fully configured...` exists at this time because Charmed OpenSearch requires TLS to be configured before use, to ensure data is encrypted in transit for the HTTP and Transport layers. We will do this in the next step.

If you're seeing the following status message:
```shell
vm.swappiness should be 0 - net.ipv4.tcp_retries2 should be 5
```
you need to [set the correct kernel parameters](/t/9724) to continue.


**Next step:** [3. Enable TLS](/t/9718)