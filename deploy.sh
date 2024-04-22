#!/bin/sh
REGION=ca-central-1
ENVIRONMENT=${1:-staging}
CLUSTER_NAME=$ENVIRONMENT-renegade-dealer-cluster
SERVICE_NAME=$ENVIRONMENT-renegade-dealer-service
TASK_FAMILY=$ENVIRONMENT-renegade-dealer-task-def
ECR_URL=377928551571.dkr.ecr.ca-central-1.amazonaws.com/renegade-dealer-$ENVIRONMENT

# Fetch the latest image URI from ECR
IMAGE_URI=$(aws ecr describe-images --repository-name renegade-dealer-$ENVIRONMENT --region $REGION --query 'sort_by(imageDetails,& imagePushedAt)[-1].imageTags[0]' --output text)
FULL_IMAGE_URI="$ECR_URL:$IMAGE_URI"
echo "Using image URI: $FULL_IMAGE_URI"

# Fetch the existing definition of the task and create a new revision with the updated URI
TASK_DEFINITION=$(aws ecs describe-task-definition --task-definition $TASK_FAMILY --region $REGION --query 'taskDefinition')
NEW_TASK_DEF=$(echo $TASK_DEFINITION | \
  jq --arg IMAGE_URI "$FULL_IMAGE_URI" '.containerDefinitions[0].image = $IMAGE_URI' | \
  jq 'del(.taskDefinitionArn)' | \
  jq 'del(.revision)' | \
  jq 'del(.status)' | \
  jq 'del(.requiresAttributes)' | \
  jq 'del(.compatibilities)' | \
  jq 'del(.registeredAt)' | \
  jq 'del(.registeredBy)' | \
  jq -c)

# Register the new task definition
NEW_TASK_INFO=$(aws ecs register-task-definition --cli-input-json "$NEW_TASK_DEF" --region $REGION)
NEW_REVISION=$(echo $NEW_TASK_INFO | jq -r '.taskDefinition.revision')
echo "Created new task revision: $NEW_REVISION"

# Update the ECS cluster to the new revision
aws ecs update-service --cluster $CLUSTER_NAME --service $SERVICE_NAME --task-definition $TASK_FAMILY:$NEW_REVISION --region $REGION >/dev/null 2>&1
echo "ECS cluster updated to new revision"
