---
myst:
  html_meta:
    description: "Optimize Charmed OpenSearch performance using testing and production profiles to configure resources and JVM heap size."
---

(how-to-optimize-cluster-performance)=
# How to optimize cluster performance with profiles

This guide shows how to configure performance profiles for Charmed OpenSearch
to match your workload requirements.

Charmed OpenSearch supports two profiles:

* **`testing`** — lightweight workloads (1 GB heap, minimum 1 node)
* **`production`** — production workloads (50% RAM heap, minimum 3+3 nodes)

## Deploy with the `testing` profile

```shell
juju deploy opensearch --channel=2/edge --config profile=testing
```

The `testing` profile allows a single node and sets JVM heap to 1 GB.
TLS is still required.

```{note}
A warning will appear in logs indicating the testing profile is active.
This profile is not suitable for production.
```

## Deploy with the `production` profile

```shell
juju deploy opensearch --channel=2/edge --config profile=production -n 3
```

The `production` profile enforces:

* Minimum 3 cluster manager nodes
* Minimum 3 data nodes
* Recommended memory: 8 GB per node
* JVM heap: 50% of available RAM (minimum 4 GB, maximum 31 GB)

If requirements are not met, the charm remains `blocked` until corrected.

## Change the profile at runtime

The profile can be changed after deployment:

```shell
juju config opensearch profile=<profile>
```

Where `<profile>` is `testing` or `production`. The charm automatically reconfigures
the cluster to match the new profile requirements.

## Profile comparison

Both profiles require swap disabled and `vm.max_map_count >= 262144`.

| Setting            | `testing`                   | `production`                              |
| :----------------- | :-------------------------- | :---------------------------------------- |
| Cluster size       | Minimum 1 node              | Minimum 3 cluster manager + 3 data nodes  |
| Memory requirement | None enforced               | Recommended 8 GB                          |
| JVM heap           | Fixed 1 GB                  | 50% of RAM (min 4 GB, max 31 GB)          |
| Use case           | Development / testing       | Production workloads                      |

## Expected result

After applying a profile, `juju status` shows the OpenSearch application `active` with the
chosen profile.

## Next steps

* [Deploy on LXD](how-to-deploy-lxd) — deploy a cluster with a specific profile.
* [Scale down safely](how-to-scale-horizontally) — adjust cluster size after changing the profile.

