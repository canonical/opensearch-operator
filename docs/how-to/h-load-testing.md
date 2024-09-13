# How to perform load testing on Charmed OpenSearch

This guide will go over the steps for load testing your OpenSearch deployment with COS on AWS as the underlying cloud. These steps can be applied to Charmed OpenSearch on other types of private and public clouds. For more information, [check Juju's supported clouds documentation](https://juju.is/docs/juju/cloud)

## Prerequisites
* `juju v3.0+`
  * This guide was written using `v3.4`
* [`jq` command-line tool](https://jqlang.github.io/jq/)  
* If not already available, [a VPC set up on AWS](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-getting-started.html) (or the equivalent environment in your cloud of choice)
* `ACCESS_KEY` and `SECRET_KEY` for AWS. 

## Summary
* [Installation and configuration](#installation-and-configuration)
* [Access Prometheus and Grafana](#access-prometheus-and-grafana)
* [Deploy OpenSearch](#deploy-opensearch)
* [Integrate with COS](#integrate-with-cos)
* [Run OpenSearch benchmark](#run-opensearch-benchmark)

---

## Installation and configuration
In this section, we will set up [Juju](#set-up-juju) and [COS](#set-up-cos).

In the case of AWS, the first step is to select or setup a VPC for this test. We recommend to use one VPC with:
* 1x public network with a jump host to allow the testing environment to be accessed
  * One tools for this is [`sshuttle`](https://manpages.ubuntu.com/manpages/jammy/man1/sshuttle.1.html)
* 1x private network (contains all the testing assets, such as OpenSearch nodes): it is not externally accessible and ensures deployments are isolated from internet access

### Set up Juju
To use AWS with a VPC, set up the Juju controller as follows. <!-- TODO: Clarify which Juju docs: If another cloud is used, please follow the steps in the Juju documentation.--> Define the following environment variables: 
* `JUJU_CONTROLLER_NAME`: controller name of choice
* `VPC_ID`: ID from AWS
* `VPC_PRIVATE_CIDR`: network range where the deployment will happen
* `K8S_CLOUD_NAME`: the k8s cluster name to be used on COS deployment later in this doc

Add credentials with the following command:

```none
juju add-credentials aws
```
Example output:
```none
This operation can be applied to both a copy on this client and to the one on a controller.
No current controller was detected but there are other controllers registered: use -c or --controller to specify a controller if needed.
Do you ONLY want to add a credential to this client? (Y/n): Y

Enter credential name: aws_creds

Regions
  us-east-1
  us-east-2
  us-west-1
  us-west-2
  ca-central-1
  eu-west-1
  eu-west-2
  eu-west-3
...

Select region [any region, credential is not region specific]: us-east-1

Using auth-type "access-key".

Enter access-key: 

Enter secret-key: 

Credential "aws_creds" added locally for cloud "aws".
```
Then, bootstrap the controller with the previously defined environment variables:

```none
juju bootstrap aws $JUJU_CONTROLLER_NAME \
    --credential aws_creds \
    --model-default container-networking-method=local \
    --config vpc-id=$VPC_ID \
    --config vpc-id-force=true \
    --constraints 'instance-type=t2.medium  root-disk=100G' \
    --to subnet=$VPC_PRIVATE_CIDR
```

### Set up COS

#### Deploy Kubernetes
Deploy a K8s cluster.

>  This document uses Microk8s. Installation instructions can be found [in COS documentation](https://charmhub.io/topics/canonical-observability-stack/tutorials/install-microk8s#heading--configure-microk8s).

Optionally, configure `kubectl` with `microk8s`’s access:

```none
# If kubectl is not yet available
sudo snap install kubectl --classic \
    --channel=<same as microk8s>

sudo microk8s config > ~/.kube/config
```

#### Deploy COS
The remainder of this section will consider that you have successfully deployed a K8s cluster and your local `kubectl` is configured to connect with that cluster. The cluster must be configured with a LoadBalancer service.

[Download the COS overlay bundle](https://github.com/canonical/cos-lite-bundle/blob/main/overlays/offers-overlay.yaml).

Add the K8s cluster to Juju as new cloud:
```none
juju add-k8s $K8S_CLOUD_NAME \
    --client --controller $JUJU_CONTROLLER_NAME
juju add-model cos $K8S_CLOUD_NAME

# Get the overlay that sets cos offerings up
wget https://raw.githubusercontent.com/canonical/cos-lite-bundle/main/overlays/offers-overlay.yaml
juju deploy cos-lite --trust \
    --overlay ./offers-overlay.yaml
```

## Access Prometheus and Grafana

Once the deployment is complete, check the IP that Traefik’s Load Balancer service got allocated:
```none
kubectl get svc -A | grep traefik | grep LoadBalancer | awk '{print $5}'
```

The password for grafana can be retrieved with the following command:

```none
juju run -m cos grafana/leader get-admin-password
```

Access the Prometheus and Grafana respectively on:
* `http://<TRAEFIK_IP>/cos-prometheus-0/graph`
* `http://<TRAEFIK_IP>/cos-grafana`

`cos-grafana` has the username “admin”.

## Deploy OpenSearch

Add a model to your controller and configure it:
```none
juju add-model opensearch aws \
    --config container-networking-method=local \
    --config vpc-id=$VPC_ID \
    --config vpc-id-force=true

juju model-config cloudinit-userdata="postruncmd:
        - [ 'sysctl', '-w', 'vm.max_map_count=262144' ]
        - [ 'sysctl', '-w', 'fs.file-max=1048576' ]
        - [ 'sysctl', '-w', 'vm.swappiness=0' ]
        - [ 'sysctl', '-w', 'net.ipv4.tcp_retries2=5' ]"

juju add-space -m opensearch internal-space \
    $VPC_PRIVATE_CIDR
```

Deploy the `self-signed-certificates` charm, create a storage pool, and integrate with `opensearch`:
```none
juju deploy self-signed-certificates \
    --constraints="arch=amd64 instance-type=t2.medium root-disk=100G spaces=internal-space" \
    --bind "internal-space"

juju create-storage-pool \
    opensearch ebs volume-type=gp3

juju deploy opensearch \
    --channel=2/edge -n3 \
    --constraints="arch=amd64 instance-type=r5.xlarge root-disk=200G spaces=internal-space" \
    --bind "internal-space" \
    --storage opensearch-data=opensearch,512G

juju integrate self-signed-certificates opensearch
```

## Integrate with COS
Import the Juju relation offers from COS into OpenSearch’s model:

```
juju consume admin/cos.alertmanager-karma-dashboard
juju consume admin/cos.grafana-dashboards
juju consume admin/cos.loki-logging
juju consume admin/cos.prometheus-receive-remote-write
```

And relate it with OpenSearch:

```
juju deploy grafana-agent
juju integrate opensearch grafana-agent
juju integrate grafana-agent grafana-dashboards
juju integrate grafana-agent loki-logging
juju integrate grafana-agent prometheus-receive-remote-write
```

## Run OpenSearch benchmark

### (Optional) Add a machine to manage the workload

```none
juju deploy ubuntu \
--constraints="arch=amd64 instance-type=r5.xlarge root-disk=opensearch,512G" --bind internal-space
```

### Discover the cluster details

Discover the IP and password to be used for this test. Set them as environment variable  `OPENSEARCH_PWD`.

```none
juju run opensearch/leader get-password 
```
Pick the password and set to the environment variable `OPENSEARCH_PWD`.

### Start the benchmark
Update or install dependencies:
```none
sudo apt update
sudo apt upgrade -y # if needed
sudo apt install -y python3-pip

pip install opensearch-benchmark
```
The `opensearch-benchmark` command can be executed with the different workloads now. Set the opensearch hosts and start test:
```none
export OPENSEARCH_HOSTS="$(juju status --format=json | jq -r '.applications.opensearch.units[] | ."public-address"' | sed 's/.*/https:\/\/&:9200/' | paste -s -d, -)"

opensearch-benchmark execute-test \
    --target-hosts $OPENSEARCH_HOSTS \
    --pipeline benchmark-only \
    --workload nyc_taxis \
    --client-options basic_auth_user:admin,basic_auth_password:$OPENSEARCH_PWD,verify_certs:false
```