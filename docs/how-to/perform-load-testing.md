---
myst:
  html_meta:
    description: "Perform load testing on Charmed OpenSearch deployments with COS monitoring on AWS and other cloud platforms."
---

(how-to-perform-load-testing)=
# How to perform load testing

This guide shows how to run load tests against a Charmed OpenSearch deployment
using [opensearch-benchmark](https://github.com/opensearch-project/opensearch-benchmark).
The example uses AWS, but the approach applies to any
[Juju-supported cloud](https://juju.is/docs/juju/cloud).

## Prerequisites

* Juju 3.6 (latest LTS)
* [`jq`](https://jqlang.github.io/jq/)
* A VPC on AWS (or equivalent in your cloud)
* AWS `ACCESS_KEY` and `SECRET_KEY`

## Set up the environment

<!-- vale off -->
(perf-juju)=
<!-- vale on -->
### Set up Juju

Define environment variables:

```shell
export JUJU_CONTROLLER_NAME=<controller-name>
export VPC_ID=<vpc-id>
export VPC_PRIVATE_CIDR=<private-subnet-cidr>
export K8S_CLOUD_NAME=<k8s-cloud-name>
```

Add AWS credentials and bootstrap:

```shell
juju add-credentials aws
juju bootstrap aws $JUJU_CONTROLLER_NAME \
    --credential aws_creds \
    --model-default container-networking-method=local \
    --config vpc-id=$VPC_ID \
    --config vpc-id-force=true \
    --constraints 'instance-type=t2.medium root-disk=100G' \
    --to subnet=$VPC_PRIVATE_CIDR
```

(perf-cos)=
### Set up COS (optional, for monitoring)

Deploy a K8s cluster (e.g. MicroK8s) and add it to Juju.
See [COS installation guide](https://documentation.ubuntu.com/observability/track-2/tutorial/installation/cos-lite-microk8s-sandbox/#configure-microk8s).

```shell
juju add-k8s $K8S_CLOUD_NAME --client --controller $JUJU_CONTROLLER_NAME
juju add-model cos $K8S_CLOUD_NAME
wget https://raw.githubusercontent.com/canonical/cos-lite-bundle/main/overlays/offers-overlay.yaml
juju deploy cos-lite --trust --overlay ./offers-overlay.yaml
```

### Access Grafana (optional)

Retrieve the Traefik load balancer IP and the Grafana admin password:

```shell
kubectl get svc -A | grep traefik | grep LoadBalancer | awk '{print $5}'
juju run -m cos grafana/leader get-admin-password
```

Access Grafana at `http://<traefik-ip>/cos-grafana` (username: `admin`).

## Deploy OpenSearch

Create a model with the required network and kernel configuration:

```shell
juju add-model opensearch aws \
    --config container-networking-method=local \
    --config vpc-id=$VPC_ID \
    --config vpc-id-force=true

juju model-config cloudinit-userdata="postruncmd:
        - [ 'sysctl', '-w', 'vm.max_map_count=262144' ]
        - [ 'sysctl', '-w', 'fs.file-max=1048576' ]
        - [ 'sysctl', '-w', 'vm.swappiness=0' ]"

juju add-space -m opensearch internal-space $VPC_PRIVATE_CIDR
```

Deploy OpenSearch with dedicated storage:

```shell
juju deploy self-signed-certificates \
    --constraints="arch=amd64 instance-type=t2.medium root-disk=100G spaces=internal-space" \
    --bind "internal-space"

juju create-storage-pool opensearch ebs volume-type=gp3

juju deploy opensearch \
    --channel=2/edge -n3 \
    --constraints="arch=amd64 instance-type=r5.xlarge root-disk=200G spaces=internal-space" \
    --bind "internal-space" \
    --storage opensearch-data=opensearch,512G

juju integrate self-signed-certificates opensearch
```

## Integrate with COS (optional)

Consume the COS offers and integrate Grafana Agent with OpenSearch:

```shell
juju consume admin/cos.grafana-dashboards
juju consume admin/cos.loki-logging
juju consume admin/cos.prometheus-receive-remote-write

juju deploy grafana-agent
juju integrate grafana-agent opensearch:cos-agent
juju integrate grafana-agent grafana-dashboards
juju integrate grafana-agent loki-logging
juju integrate grafana-agent prometheus-receive-remote-write
```

## Run the benchmark

Retrieve the admin password:

```shell
juju run opensearch/leader get-password
export OPENSEARCH_PWD=<password>
```

Install opensearch-benchmark:

```shell
pip install opensearch-benchmark
```

Build the host list and execute:

```shell
export OPENSEARCH_HOSTS="$(juju status --format=json | jq -r '.applications.opensearch.units[] | ."public-address"' | sed 's/.*/https:\/\/&:9200/' | paste -s -d, -)"

opensearch-benchmark run \
    --target-hosts $OPENSEARCH_HOSTS \
    --pipeline benchmark-only \
    --workload nyc_taxis \
    --client-options basic_auth_user:admin,basic_auth_password:$OPENSEARCH_PWD,verify_certs:false
```

See the [opensearch-benchmark documentation](https://opensearch.org/docs/latest/benchmark/)
for additional workloads and options.

## Expected result

The benchmark completes and prints a summary report with throughput, latency, and error metrics.
If COS is integrated, the Grafana **Charmed OpenSearch** dashboard shows the load spike during the test.

## Next steps

* [Optimize cluster performance with profiles](how-to-optimize-cluster-performance) — tune resource allocation based on benchmark results.
* [Enable monitoring (COS)](how-to-monitoring) — set up ongoing observability.
