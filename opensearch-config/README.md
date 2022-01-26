# About
This folder contains CloudFormation configurations for an AWS OpenSearch cluster and a set of Logstash servers behind a load balancer.

# Usage
You'll need appropriate AWS permissions (to create and monitor resources). Put AWS credentials in `~/.aws/credentials` and run `deploy_opensearch.sh`.

# After Creation
OpenSearch users

* Create a user with username 'logstash' and the entered password in OpenSearch, and assign it the "logstash" role.
* Create a user with username 'readonly' and password 'opensearch-readonly-PUBLIC-2021!' in OpenSearch, and grant it read-only privileges. Give it access to the Global tenant.

In the OpenSearch Dashboard select `Index Management`, `State management policies`, and then `Create Policy`. Make a policy with the following policy statement:
```
{
    "policy_id": "DeleteAllDataAfter14Days",
    "description": "Delete all data after 14 days",
    "last_updated_time": 1639608774297,
    "schema_version": 1,
    "error_notification": null,
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
            "actions": [],
            "transitions": []
        }
    ],
    "ism_template": null
}
```
This will delete all indices that are at least 7 days old (e.g. the `logstash-logs-2021.12.15` index will be deleted on 2021-12-22).
