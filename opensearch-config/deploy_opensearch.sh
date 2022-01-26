# Delete stack if it exists
echo "Deleting ECR stack..."
aws cloudformation delete-stack --stack-name ecr-stack
echo "Waiting 2 minutes (press enter to continue)..."
read -t 120 NullVariable

# Create stack
echo ""
echo "Creating ECR stack..."
aws cloudformation create-stack --stack-name ecr-stack --template-body file://ecr.yaml
echo "Waiting 60 minutes (press enter to continue)..."
read -t 3600 NullVariable

# Deploy stack
echo ""
echo "Deploying ECR stack..."
aws cloudformation deploy --stack-name ecr-stack --template-file ecr.yaml

# Get logstash password from user:
echo "Enter desired password for Logstash user (the OpenSearch user account that Logstash will use to write to OpenSearch)."
echo "Must NOT include these characters ()\"&|![]"
read -p "Password: " logstashPassword

# Write this password to config/output.conf (we'll overwrite it at the end of this file)
# Note that the -i (in-place) option doesn't work on MacOS, so we write to a temporary file and then move it
sed "s/password => \"DO-NOT-COMMIT-TO-VERSION-CONTROL\"/password => \"$logstashPassword\"/g" config/output.conf > config/tmp.conf
mv config/tmp.conf config/output.conf

# Build Docker image for Logstash
docker build -t openstack-logstash-repository . --no-cache

# Erase password from config/output.conf
sed "s/password => \"$logstashPassword\"/password => \"DO-NOT-COMMIT-TO-VERSION-CONTROL\"/g" config/output.conf > config/tmp.conf
mv config/tmp.conf config/output.conf

# ECR login
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 035559393697.dkr.ecr.us-east-1.amazonaws.com

# Tag the image
docker tag openstack-logstash-repository:latest 035559393697.dkr.ecr.us-east-1.amazonaws.com/openstack-logstash-repository:latest

# Push the image
docker push 035559393697.dkr.ecr.us-east-1.amazonaws.com/openstack-logstash-repository:latest

# If you push a new version of this Docker container, you can deploy it to an existing ECS stack like so:
#     aws ecs update-service --cluster pre-prod-Cluster --service pre-prod-ECSService --force-new-deployment
# (replace "pre-prod-Cluster" and "pre-prod-ECSService" with the correct cluster/stack names). This is a zero-downtime operation.

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
aws cloudformation create-stack --stack-name opensearchteststack --template-body file://opensearch.yaml --parameters ParameterKey=SSHKey,ParameterValue=aws-keypair-2021-03-22 --capabilities CAPABILITY_NAMED_IAM
echo "Waiting 60 minutes (press enter to continue)..."
read -t 3600 NullVariable

# Create Logstash Cluster stack
aws cloudformation create-stack --stack-name logstashstack --template-body file://logstash_cluster.yaml --capabilities CAPABILITY_NAMED_IAM

echo "Final steps:"
echo "   * Create a user with username 'logstash' and the entered password in OpenSearch, and assign it the \"logstash\" role"
echo "   * Create a user with username 'readonly' and password 'opensearch-readonly-PUBLIC-2021!' in OpenSearch, and grant it read-only privileges"
