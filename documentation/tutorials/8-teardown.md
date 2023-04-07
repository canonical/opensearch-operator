# Cleanup and extra info

## Remove Charmed OpenSearch and Juju

***Warning:** when you remove Charmed OpenSearch as shown below you will lose all the data in your cluster. Furthermore, when you remove Juju as shown below you will lose access to any other applications you have hosted on Juju.*

To remove Charmed OpenSearch and the model it is hosted on, run this command:

```bash
juju destroy-model tutorial --destroy-storage --force --no-wait
```

Next step is to remove the Juju controller. You can see all of the available controllers by entering `juju controllers`. To remove the controller enter:

```bash
juju destroy-controller opensearch-demo
```

Finally to remove Juju altogether, enter:

```bash
sudo snap remove juju --purge
```

## Next Steps

In this tutorial we've successfully deployed OpenSearch, added/removed units from the cluster, added/removed users to/from the database, and even enabled and disabled TLS. You may now keep your Charmed OpenSearch deployment running and write to the database or remove it entirely using the steps in [Remove Charmed Opensearch and Juju](#remove-charmed-opensearch-and-juju). If you're looking for what to do next you can:

- Check out other charms on [charmhub.io](https://charmhub.io/)
- Read about [High Availability Best Practices](https://canonical.com/blog/database-high-availability)
- [Report](https://github.com/canonical/opensearch-operator/issues) any problems you encountered.
- [Give us your feedback](https://chat.charmhub.io/charmhub/channels/data-platform).
- [Contribute to the code base](https://github.com/canonical/opensearch-operator)
