---
myst:
  html_meta:
    description: "Understand Charmed OpenSearch performance profiles, JVM heap sizing, and resource requirements for testing and production deployments."
---

(explanation-performance-profiles)=
# Performance profiles

Charmed OpenSearch provides **performance profiles** that tune resource allocation and
OpenSearch parameters to suit different use cases. Profiles simplify deployment by
automatically configuring JVM heap size, node count requirements, and system-level
constraints based on the intended workload.

## Why profiles exist

OpenSearch is sensitive to resource configuration. Setting JVM heap too low causes
out-of-memory errors; setting it too high wastes RAM and can cause long garbage collection
pauses. Node count affects cluster stability: a single node cannot provide high availability.

Profiles encapsulate these best practices so that users do not need to manually tune
JVM heap, memory limits, and node constraints. They also enforce safety checks: for example,
the `production` profile will block deployment if the minimum node count is not met.

## Available profiles

Charmed OpenSearch supports two profiles:

| Setting | `testing` | `production` |
| :--- | :--- | :--- |
| Cluster size | Minimum 1 node (cluster manager + data) | Minimum 3 cluster manager + 3 data nodes |
| Memory requirement | None enforced | Minimum 8 GB per node |
| JVM heap | Fixed at 1 GB | 50% of available RAM (min 4 GB, max 31 GB) |
| Use case | Development, testing, lightweight workloads | Production workloads and large deployments |

### The `testing` profile

Designed for development and testing on a single host. It allows a cluster to run with
a single node and sets the JVM heap to a fixed 1 GB. No strict memory requirements are
enforced. A warning is logged indicating that this profile is not suitable for production.

### The `production` profile

Designed for production workloads. It enforces:

- A minimum of 3 cluster manager nodes and 3 data nodes for high availability.
- JVM heap set to 50% of available RAM, capped at 31 GB. Since the profile also requires at
  least 8 GB of RAM per node, the heap is effectively at least 4 GB.
  This follows the
  [OpenSearch recommendation](https://opensearch.org/docs/latest/tuning-your-cluster/performance/)
  to allocate roughly half of available RAM to the JVM heap, leaving the rest for the
  operating system file cache.
- A minimum of 8 GB of RAM per node.

If any of these requirements are not met, the charm remains in a `blocked` state until
corrected.

## System prerequisites

Both profiles enforce the same system-level prerequisites:

- **Swap must be disabled** — OpenSearch performs best when it is not swapped to disk.
- `vm.max_map_count >= 262144` — required by OpenSearch for mmap-based file access.

Setting `fs.file-max = 1048576` is strongly recommended to ensure sufficient file descriptors
for large deployments, but it is not currently enforced by either profile.

The `net.ipv4.tcp_retries2` parameter is set automatically by the charm and does not
need to be configured manually.

For instructions on how to apply these settings, see
[How to deploy on LXD](how-to-deploy-lxd). For the full list of required kernel parameters,
see [System requirements](reference-system-requirements).

## Changing profiles

The profile can be changed after deployment. The charm automatically detects the update
and reconfigures the instance to match the new profile's requirements.

```shell
juju config opensearch profile=<profile>
```

Where `<profile>` is `testing` or `production`.

```{note}
Switching from `testing` to `production` may cause the charm to enter a `blocked` state
if the current node count does not meet the production minimum (3 cluster manager + 3 data nodes).
Scale up the cluster before switching profiles.
```

## See also

* [How to optimize cluster performance with profiles](how-to-optimize-cluster-performance) — step-by-step guide.
* [System requirements](reference-system-requirements) — hardware, software, and kernel parameter requirements.
* [Node roles and cluster topology](explanation-node-roles) — how node roles relate to cluster sizing.
