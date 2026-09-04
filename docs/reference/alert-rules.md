---
myst:
  html_meta:
    description: "Monitor Charmed OpenSearch with Canonical Observability Stack (COS) using Grafana, Prometheus metrics, and alert rules."
---

(ref-alert-rules)=
# Default alert rules

The following alert rules are set by default in Charmed OpenSearch.

<table>
   <thead>
      <tr>
         <th>Alert</th>
         <th>Severity</th>
         <th>Notes</th>
      </tr>
   </thead>
   <tbody>
      <tr>
         <td>OpenSearchScrapeFailed</td>
         <td><img src="https://img.shields.io/badge/critical-red" alt="critical" width="47" height="20" loading="lazy" style="aspect-ratio: 47 / 20;"></td>
         <td>Triggered when the prometheus scrape fails.</td>
      </tr>
      <tr>
         <td>OpenSearchClusterRed</td>
         <td><img src="https://img.shields.io/badge/critical-red" alt="critical" width="47" height="20" loading="lazy" style="aspect-ratio: 47 / 20;"></td>
         <td>Triggered when the health status of the cluster is red, meaning that principal shards are not allocated.</td>
      </tr>
      <tr>
         <td>OpenSearchClusterYellowTemp</td>
         <td><img src="https://img.shields.io/badge/warning-yellow" alt="warning" width="47" height="20" loading="lazy" style="aspect-ratio: 47 / 20;"></td>
         <td>Triggered when shards are still reallocating or initializing.</td>
      </tr>
      <tr>
         <td>OpenSearchClusterYellow</td>
         <td><img src="https://img.shields.io/badge/warning-yellow" alt="warning" width="47" height="20" loading="lazy" style="aspect-ratio: 47 / 20;"></td>
         <td>Triggered when some replicas shards are unassigned. Might require scale the application to host all shards</td>
      </tr>
      <tr>
         <td>OpenSearchWriteRequestsRejectionJumps</td>
         <td><img src="https://img.shields.io/badge/warning-yellow" alt="warning" width="47" height="20" loading="lazy" style="aspect-ratio: 47 / 20;"></td>
         <td>Triggered when the write request rejection is bigger than 5%. Might indicate that the node may not keep up with the indexing speed.</td>
      </tr>
      <tr>
         <td>OpenSearchNodeDiskLowWatermarkReached</td>
         <td><img src="https://img.shields.io/badge/warning-yellow" alt="warning" width="47" height="20" loading="lazy" style="aspect-ratio: 47 / 20;"></td>
         <td>Triggered when disks reach 85% of the capacity.</td>
      </tr>
      <tr>
         <td>OpenSearchNodeDiskHighWatermarkReached</td>
         <td><img src="https://img.shields.io/badge/high-red" alt="high" width="47" height="20" loading="lazy" style="aspect-ratio: 47 / 20;"></td>
         <td>Triggered when disks reach 90% of the capacity.</td>
      </tr>
      <tr>
         <td>OpenSearchJVMHeapUseHigh</td>
         <td><img src="https://img.shields.io/badge/alert-yellow" alt="alert" width="47" height="20" loading="lazy" style="aspect-ratio: 47 / 20;"></td>
         <td>Triggered when the JVM Heap usage in a node reaches 75%.</td>
      </tr>
      <tr>
         <td>OpenSearchHostSystemCPUHigh</td>
         <td><img src="https://img.shields.io/badge/alert-yellow" alt="alert" width="47" height="20" loading="lazy" style="aspect-ratio: 47 / 20;"></td>
         <td>Triggered when system CPU usage in a node reaches 90%.</td>
      </tr>
      <tr>
         <td>OpenSearchProcessCPUHigh</td>
         <td><img src="https://img.shields.io/badge/alert-yellow" alt="alert" width="47" height="20" loading="lazy" style="aspect-ratio: 47 / 20;"></td>
         <td>Triggered when process CPU usage in a node reaches 90%.</td>
      </tr>
      <tr>
         <td>OpenSearchThrottling</td>
         <td><img src="https://img.shields.io/badge/warning-yellow" alt="warning" width="47" height="20" loading="lazy" style="aspect-ratio: 47 / 20;"></td>
         <td>Triggered when a cluster is throttling. Might indicate that is necessary to review indexing request rate, index lifecycle or scale the application.</td>
      </tr>
      <tr>
         <td>OpenSearchThrottlingTooLong</td>
         <td><img src="https://img.shields.io/badge/critical-red" alt="critical" width="47" height="20" loading="lazy" style="aspect-ratio: 47 / 20;"></td>
         <td>Triggered when a cluster is constantly throttling for at least 20 minutes. Might indicate that is necessary to review indexing request rate, index lifecycle or scale the application.</td>
      </tr>
   </tbody>
</table>
