# Infrastructure changelog

## Changelog

#### 13.03.2022

What has been done:

- recreated Opensearch cluster
  - resize storage from 50GB to 1TB
- changed cloudformation stack name from opensearchteststack to opensearchstack,
- added security rule that allows logscraper01.openstack.org to push logs to the Logstash service,
- renamed Logstash container service deployment from pre-prod-Cluster to production-Cluster.

Executed commands:

``` shell
# Delete stacks if they exist
echo "Deleting Logstash stack..."
aws cloudformation delete-stack --stack-name logstashstack
echo "Waiting 60 minutes (press enter to continue)..."
read -t 3600 NullVariable

echo "Deleting Opensearch stack..."
aws cloudformation delete-stack --stack-name opensearchteststack
echo "Waiting 60 minutes (press enter to continue)..."
read -t 3600 NullVariable

# Create OpenSearch Cluster stack
echo ""
echo "Creating Opensearch stack..."
aws cloudformation create-stack --stack-name opensearchstack --template-body file://opensearch.yaml --parameters ParameterKey=SSHKey,ParameterValue=my-keypair --capabilities CAPABILITY_NAMED_IAM
echo "Waiting 60 minutes (press enter to continue)..."
read -t 3600 NullVariable

# Create Logstash Cluster stack
aws cloudformation create-stack --stack-name logstashstack --template-body file://logstash_cluster.yaml --capabilities CAPABILITY_NAMED_IAM
```

Different changes to CloudFormatino templates have different "update behaviors".
For example, changing the EBS configuration of an OpenSearch cluster requires
"No interruption" ([source](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchservice-domain.html#cfn-opensearchservice-domain-ebsoptions)).
Others (like changing the name of a CloudFormation stack or a load balancer) require total replacement.
Those update behaviors are documented [here](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-update-behaviors.html).
If you're deploying a change that doesn't require resource replacement, you can run the "update-stack" commands:

```shell
aws cloudformation update-stack --stack-name opensearchstack --template-body file://opensearch.yaml --parameters ParameterKey=SSHKey,ParameterValue=my-keypair --capabilities CAPABILITY_NAMED_IAM
aws cloudformation update-stack --stack-name logstashstack --template-body file://logstash_cluster.yaml --capabilities CAPABILITY_NAMED_IAM
```

#### 15.12.2021

What has been done:

- creted cloudformation stack for Logstash,
- created Opensearch cluster,
- created readonly user and readonly role,
- deployed logscraper, loggearman-client and loggearman-worker services on logscraper01.openstack.org.

Configuration has been describe `here <https://review.opendev.org/c/openstack/ci-log-processing/+/826405>`__.
