---
myst:
  html_meta:
    description: "Deep-dive explanations of Charmed OpenSearch concepts including security, encryption, and authentication."
---

(explanation-index)=
# Explanation

The pages in this section aim to provide additional context and deeper understanding
of foundational topics and concepts relevant to OpenSearch.

## Cluster architecture

* [Node roles and cluster topology](explanation-node-roles) — how node roles, data tiers, and the main orchestrator pattern work in large deployments.
* [Cluster health and scaling](explanation-cluster-health) — understanding green/yellow/red health states and safe scaling practices.
* [Performance profiles](explanation-performance-profiles) — how profiles tune JVM heap, node count, and resource requirements.
* [Persistent storage and disk recovery](explanation-persistent-storage) — risks of disk reuse, dangling indices, and last-resort disaster recovery.

## Security

Secure deployments of Charmed OpenSearch can be achieved through using recommended configurations,
including setting up encryption and authentication.
For more details, see the [Security](explanation-security-index) topic overview,
[Cryptography](explanation-security-cryptography), and
[TLS certificates](explanation-tls-certificates) explanation pages.

## Testing and monitoring

For a deeper understanding of monitoring in Charmed OpenSearch,
see the [Monitoring](explanation-monitoring) explanation page.

Overview of our approach to testing Charmed OpenSearch is summarized in the
[](explanation-software-testing) page.

```{toctree}
:titlesonly:
:hidden:

Node roles <node-roles>
cluster-health
performance-profiles
Persistent storage <persistent-storage>
Security <security/index>
monitoring
Software testing <software-testing>
```
