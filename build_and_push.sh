#!/bin/sh
REGION=ca-central-1
ENVIRONMENT=${1:-staging}
ECR_URL=377928551571.dkr.ecr.ca-central-1.amazonaws.com/renegade-dealer-$ENVIRONMENT

docker build -t dealer:latest .
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ECR_URL

docker tag dealer:latest $ECR_URL:latest
docker push $ECR_URL:latest
