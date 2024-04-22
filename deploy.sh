#!/bin/sh
REGION=ca-central-1
ENVIRONMENT=${1:-staging}
CLUSTER_NAME=$ENVIRONMENT-renegade-dealer-cluster
SERVICE_NAME=$ENVIRONMENT-renegade-dealer-service

# Update the ECS service to use the latest image
aws ecs update-service --region $REGION --cluster $CLUSTER_NAME --service $SERVICE_NAME --force-new-deployment
