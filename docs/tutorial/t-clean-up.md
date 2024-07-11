> [Charmed OpenSearch Tutorial](/t/9722) > 7. Clean up the environment

# Clean up the environment
In this tutorial, we’ve successfully:

* Deployed OpenSearch on LXD
* Enabled TLS
* Integrated with a client application
* Rotated user credentials
* Scaled our deployment

You may now keep your OpenSearch deployment running to continue experimenting, or remove it entirely to free up resources on your machine.

## Remove Charmed OpenSearch
[note type="caution"]
**Warning:** When you remove Charmed OpenSearch as shown below, you will lose all the data in your cluster. 
[/note]

To remove Charmed OpenSearch and the model it is hosted on, run this command:

```bash
juju destroy-model tutorial --destroy-storage --force --no-wait
```

Next step is to remove the Juju controller. You can see all of the available controllers by entering `juju controllers`. 

To remove the controller created for this tutorial, enter:

```bash
juju destroy-controller opensearch-demo
```

## Remove Juju
[note type="caution"]
**Warning:** When you remove Juju as shown below you will lose access to any other applications you have hosted on Juju.
[/note]

To remove Juju altogether, enter:

```bash
sudo snap remove juju --purge
```
---

## What next?

- Check out other charms on [charmhub.io](https://charmhub.io/)
- Read about [High Availability Best Practices](https://canonical.com/blog/database-high-availability)
- [Report](https://github.com/canonical/opensearch-operator/issues) any problems you encountered
- [Give us your feedback](https://chat.charmhub.io/charmhub/channels/data-platform).
- [Contribute to the code base](https://github.com/canonical/opensearch-operator)