# Opensearch configuration

## About

This folder contains CloudFormation configurations for an AWS OpenSearch cluster and a set of Logstash servers behind a load balancer.

## Usage

You'll need appropriate AWS permissions (to create and monitor resources). Put AWS credentials in `~/.aws/credentials` and run `deploy_opensearch.sh`.

## After Creation Opensearch

The Opensearch service requires additional configuration like creating readonly user, create logstash user etc.

### Create user

Users will be created in the Opensearch dashboards service.
We create only few internal users:

* logstash - that will be used by logstash or logsender service
* readonly - readonly user that will be able to discover data, check visualization and dashboards
* openstack - readonly user with easy to remember password

NOTE:
To skip `password_validation_regex` validation for user that should have easy to remember password, like `openstack` user,
it has been created via REST API. For example:

```shell
bcrypt=$(htpasswd -bnBC 10 "" password | tr -d ':\n')
curl -X PUT "https://<opensearch API url>/_plugins/_security/api/internalusers/openstack" \
     -H 'Content-Type: application/json' \
     -d' { "hash" : "$2a$12$ABDOLV5fJDfXlkyNVAqD0O4AcUyvCV.Pq8jqLaPdHbsj0yRZYniNa" } ' \
     --user 'admin:myuserpassword'
```

### Creating roles

Role will be added in the Opensearch dashboards service.
Created roles:

* Readonly role is creaded base on the [inscruction](https://opensearch.org/docs/latest/security-plugin/access-control/users-roles/#set-up-a-read-only-user-in-opensearch-dashboards)
Details:
  name: readonly
  cluster permissions: cluster_composite_ops_ro
  index permissions:
    index: *
    index permissions: read
  tenant permissions:
    tenant: global_tenant

### Create role mapping

After creating the role, inside the role you will be able to attach the user that should use it.

## Create ILM - Index Lifecycle Management

In the OpenSearch Dashboard select `Index Management`, `State management policies`, and then `Create Policy`. Make a policy with the following policy statement:

```json
{
    "policy": {
        "description": "Delete all data after 14 days",
        "default_state": "hot",
        "states": [
            {
                "name": "hot",
                "actions": [],
                "transitions": [
                    {
                        "state_name": "delete",
                        "conditions": {
                            "min_index_age": "14d"
                        }
                    }
                ]
            },
            {
                "name": "delete",
                "actions": [
                    {
                        "delete": {}
                    }
                ],
                "transitions": []
            }
        ]
    }
}
```

This will delete all indices that are at least 14 days old (e.g. the `logstash-logs-2021.12.15` index will be deleted on 2021-12-22).

## Advenced settings in Opensearch Dashboards

There is only few changes applied comparing to default settings.
Differences in sections:

* General

> * Timezone for date formatting

```shell
UTC
```

> * Default route:

```shell
/app/discover?security_tenant=global
```

> * Time filter quick ranges:

```json
[
  {
    "from": "now/d",
    "to": "now/d",
    "display": "Today"
  },
  {
    "from": "now/w",
    "to": "now/w",
    "display": "This week"
  },
  {
    "from": "now-15m",
    "to": "now",
    "display": "Last 15 minutes"
  },
  {
    "from": "now-30m",
    "to": "now",
    "display": "Last 30 minutes"
  },
  {
    "from": "now-1h",
    "to": "now",
    "display": "Last 1 hour"
  },
  {
    "from": "now-6h",
    "to": "now",
    "display": "Last 6 hour"
  },
  {
    "from": "now-12h",
    "to": "now",
    "display": "Last 12 hour"
  },
  {
    "from": "now-24h",
    "to": "now",
    "display": "Last 24 hours"
  },
  {
    "from": "now-7d",
    "to": "now",
    "display": "Last 7 days"
  }
]
```
