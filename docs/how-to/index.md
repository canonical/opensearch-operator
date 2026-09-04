---
myst:
  html_meta:
    description: "Step-by-step guides for deploying, managing, and maintaining Charmed OpenSearch including TLS, backups, monitoring, and scaling."
---

(how-to-index)=
# How-to guides

These guides help you accomplish specific tasks with Charmed OpenSearch on machines.

## Deployment

* [Standard deployment](how-to-deploy-standard)
* [Launch a large deployment](how-to-deploy-large)

## Security

* [Manage TLS encryption](how-to-enable-tls-encryption)
* [Manage passwords](how-to-manage-passwords)
* [Access OpenSearch using OAuth](how-to-access-using-oauth)
* [Enable JWT authentication](how-to-guides-enable-jwt-authentication)

## Operations

* [Scale a cluster horizontally](how-to-scale-horizontally)
* [Integrate with an application](how-to-integrate-with-an-application)
* [Manage persistent storage](how-to-persistent-storage)
* [Optimize cluster performance](how-to-optimize-cluster-performance)
* [Enable email notifications](how-to-guides-add-smtp-credentials)

## Backup and restore

* [Configure S3 storage](how-to-back-up-configure-s3)
* [Configure Azure storage](how-to-back-up-configure-azure-storage)
* [Create and restore backups](how-to-create-a-backup)

## Upgrades

* [Upgrade, rollback, and recover](how-to-minor-upgrade)

## Monitoring

* [Enable monitoring (COS)](how-to-monitoring)
* [Perform load testing](how-to-perform-load-testing)

```{toctree}
:titlesonly:
:hidden:

Deploy <deploy/index>
Manage TLS encryption <tls-encryption>
Manage passwords <manage-passwords>
Access using OAuth <access-using-oauth>
Enable JWT authentication <enable-jwt-authentication>
Scale a cluster <scale-horizontally>
Integrate with an application <integrate-with-an-application>
Manage persistent storage <persistent-storage>
Optimize cluster performance <optimize-cluster-performance>
Enable email notifications <add-smtp-credentials>
Back up and restore <back-up-and-restore/index>
Upgrade <upgrade>
Enable monitoring <monitoring>
Perform load testing <perform-load-testing>
```
