---
myst:
  html_meta:
    description: "Remove your Charmed OpenSearch deployment and clean up Juju resources to free up system resources after completing the tutorial."
---

<!-- test:spread
priority: 100
kill-timeout: 30m
-->

(tutorial-7-clean-up-the-environment)=
# 7. Clean up the environment

> [Charmed OpenSearch Tutorial](tutorial-index) > 7. Clean up the environment

In this tutorial, we’ve successfully:

* Deployed OpenSearch on LXD
* Enabled TLS
* Integrated with a client application
* Rotated user credentials
* Scaled our deployment

You may now keep your OpenSearch deployment running to continue experimenting or remove it entirely
to free up resources on your machine.

## Remove Charmed OpenSearch

```{warning}
When you remove Charmed OpenSearch as shown below, you will lose all the data in your cluster.
```

To remove Charmed OpenSearch and the model it is hosted on, run this command:

```shell
juju destroy-model tutorial --destroy-storage --force --no-wait
```

<!-- test:wait --seconds 10 -->

<!-- test:assert
juju models --format=json | python3 -c "
import json, sys
data = json.load(sys.stdin)
models = [m['short-name'] for m in data.get('models', [])]
assert 'tutorial' not in models, f'Model tutorial still exists: {models}'
"
-->

The next step is to remove the Juju controller.
You can see all of the available controllers by entering `juju controllers`.

To remove the controller created for this tutorial, enter:

```shell
juju destroy-controller opensearch-demo
```

Then, don't forget to delete the Juju model configuration file.

```shell
rm cloudinit-userdata.yaml
```

<!-- test:wait --seconds 10 -->

## Remove Juju

```{warning}
When you remove Juju as shown below you will lose access to any other applications
you have hosted on Juju.
```

To remove Juju altogether, enter:

```bash
sudo snap remove juju --purge
```

## Remove LXD

```{warning}
When you remove LXD as shown below you will lose access to any other applications
you have hosted on LXD.
```

You can list all your currently running LXD container with `lxc list`.

To uninstall Juju, enter:

```bash
sudo snap remove lxd --purge
```

## Reset the Kernel parameters

```{warning}
In the following command, use the values you saved during step 1 -> Get default values.
```

If you did not save those values, use the second reset option.

Leaving the custom kernel parameters outside of this tutorial scope can impact
the host machine's performance.

To reset them, you can either :

* Reboot your computer
* Set your original parameters with the following command :

```shell
sudo tee -a /etc/sysctl.conf > /dev/null <<EOT
vm.max_map_count=262144
vm.swappiness=60
fs.file-max=1048576
EOT

sudo sysctl -p
```

<!-- test:wait --seconds 5 -->

<!-- test:assert
_output=$(sysctl vm.max_map_count vm.swappiness net.ipv4.tcp_retries2 fs.file-max)
echo "$_output" | grep -q 'vm.max_map_count = 262144'  || { echo "FAIL: expected vm.max_map_count = 262144";  echo "$_output"; exit 1; }
echo "$_output" | grep -q 'vm.swappiness = 60'         || { echo "FAIL: expected vm.swappiness = 60";         echo "$_output"; exit 1; }
echo "$_output" | grep -q 'net.ipv4.tcp_retries2 = 15' || { echo "FAIL: expected net.ipv4.tcp_retries2 = 15"; echo "$_output"; exit 1; }
echo "$_output" | grep -q 'fs.file-max = 1048576'      || { echo "FAIL: expected fs.file-max = 1048576";      echo "$_output"; exit 1; }
-->

## What next?

* Check out other charms on [charmhub.io](https://charmhub.io/)
* Read about [High Availability Best Practices](https://canonical.com/blog/database-high-availability)
* [Report](https://github.com/canonical/opensearch-operator/issues) any problems you encountered
* [Give us your feedback](https://matrix.to/#/#charmhub-data-platform:ubuntu.com)
* [Contribute to the code base](https://github.com/canonical/opensearch-operator)
