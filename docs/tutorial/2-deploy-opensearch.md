---
myst:
  html_meta:
    description: "Deploy a three-unit Charmed OpenSearch cluster with Juju using performance profiles for optimal resource usage."
---

<!-- test:spread
priority: 600
kill-timeout: 60m
-->

(tutorial-2-deploy-opensearch)=
# 2. Deploy OpenSearch

> [Charmed OpenSearch Tutorial](tutorial-index) >  2. Deploy OpenSearch

Charmed OpenSearch supports performance profiles.
It is recommended in a single host deployment with LXD to use the `testing` profile,
which will only consume 1G RAM per container.

To deploy Charmed OpenSearch, run the following command:

```shell
juju deploy opensearch -n 3
```

<!-- test:await-idle --timeout 1200 --allow-blocked opensearch -->

<!-- test:assert
juju status --format=json | python3 -c "
import json, sys
data = json.load(sys.stdin)
units = data['applications']['opensearch']['units']
assert len(units) == 3, f'Expected 3 units, got {len(units)}'
for u in units.values():
    assert u['workload-status']['current'] == 'blocked', f'Expected blocked, got {u[\"workload-status\"][\"current\"]}'
"
-->

```{note}
The `-n` flag is optional and specifies the number of units to deploy.
In this case, we are deploying three units of Charmed OpenSearch.
We recommend deploying at least three units for high availability.
```

This command will fetch the charm from
[Charmhub](https://charmhub.io/opensearch) and deploy 3 units to the LXD cloud.
This process can take several minutes depending on your machine.

You can track the progress by running:

```bash
juju status --watch 1s
```

```{note}
This command is useful for checking the status of your Juju model,
including the applications and machines it hosts.
Helpful information it displays includes IP addresses, ports, state, etc.
The output of this command updates once every other second.
```

When the application is ready, `juju status` will show something similar to the sample output below:

```text
Model     Controller       Cloud/Region         Version  SLA          Timestamp
tutorial  opensearch-demo  localhost/localhost  3.6.23   unsupported  12:36:56Z

App         Version  Status   Scale  Charm       Channel   Rev  Exposed  Message
opensearch           blocked      3  opensearch  2/stable  344  no       Missing TLS relation with this cluster.

Unit           Workload  Agent  Machine  Public address  Ports  Message
opensearch/0   blocked   idle   0        10.95.38.94            Missing TLS relation with this cluster.
opensearch/1   blocked   idle   1        10.95.38.139           Missing TLS relation with this cluster.
opensearch/2*  blocked   idle   2        10.95.38.212           Missing TLS relation with this cluster.

Machine  State    Address       Inst id        Base          AZ  Message
0        started  10.95.38.94   juju-be3883-0  ubuntu@24.04      Running
1        started  10.95.38.139  juju-be3883-1  ubuntu@24.04      Running
2        started  10.95.38.212  juju-be3883-2  ubuntu@24.04      Running
```

To exit the `juju status` screen, enter `Ctrl + C`.

The status message `Missing TLS relation with this cluster.` is displayed because
Charmed OpenSearch requires TLS to be configured before use, to ensure data is encrypted in transit
for the HTTP and Transport layers. We will do this in the next step.

If you see the following status message:

```text
Missing requirements: vm.swappiness should be at most 0
```

you need to [set the correct kernel parameters](tutorial-1-set-up-the-environment) to continue.

```{note}
**Next step:** [3. Enable TLS](tutorial-3-enable-encryption)
```
