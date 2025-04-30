> [Charmed OpenSearch Tutorial](/t/9722) > 7. Clean up the environment

# Clean up the environment
In this tutorial, we’ve successfully:

* Deployed OpenSearch on LXD
* Enabled TLS
* Integrated with a client application
* Rotated user credentials
* Scaled our deployment

You may now keep your OpenSearch deployment running to continue experimenting or remove it entirely to free up resources on your machine.

## Remove Charmed OpenSearch
> **Warning:** When you remove Charmed OpenSearch as shown below, you will lose all the data in your cluster. 

To remove Charmed OpenSearch and the model it is hosted on, run this command:

```bash
juju destroy-model tutorial --destroy-storage --force --no-wait
```

The next step is to remove the Juju controller. You can see all of the available controllers by entering `juju controllers`. 

To remove the controller created for this tutorial, enter:

```bash
juju destroy-controller opensearch-demo
```

Then, don't forget to delete the Juju model configuration file.
```bash
rm cloudinit-userdata.yaml
```

## Remove Juju
> **Warning:** When you remove Juju as shown below you will lose access to any other applications you have hosted on Juju.

To remove Juju altogether, enter:

```bash
sudo snap remove juju --purge
```

## Remove LXD
> **Warning:** When you remove LXD as shown below you will lose access to any other applications you have hosted on LXD.

You can list all your currently running LXD container with `lxc list`.

To uninstall Juju, enter:

```bash
sudo snap remove lxd --purge
```

## Reset the Kernel parameters
>**Warning:** In the following command, use the values you saved during step 1 -> Get default values.

If you did not save those values, use the second reset option.

Leaving the custom kernel parameters outside of this tutorial scope can impact the host machine's performance.

To reset them, you can either :
* Reboot your computer
* Set your original parameters with the following command :

```bash
sudo tee -a /etc/sysctl.conf > /dev/null <<EOT
vm.max_map_count=262144
vm.swappiness=60
net.ipv4.tcp_retries2=15
fs.file-max=1048576
EOT

sudo sysctl -p
```

---

## What next?

- Check out other charms on [charmhub.io](https://charmhub.io/)
- Read about [High Availability Best Practices](https://canonical.com/blog/database-high-availability)
- [Report](https://github.com/canonical/opensearch-operator/issues) any problems you encountered
- [Give us your feedback](https://chat.charmhub.io/charmhub/channels/data-platform).
- [Contribute to the code base](https://github.com/canonical/opensearch-operator)