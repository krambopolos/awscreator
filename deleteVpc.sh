#!/bin/bash

# Define AWS region
REGION="us-east-1"
VPC_ID="vpc-0bcedfcde08bb0c5b"

echo "Checking for attached resources in VPC $VPC_ID..."

# Check for and detach/delete ENIs
enis=$(aws ec2 describe-network-interfaces --region $REGION --filters "Name=vpc-id,Values=$VPC_ID" --query "NetworkInterfaces[].NetworkInterfaceId" --output text)
if [ -n "$enis" ]; then
    for eni in $enis; do
        attachment=$(aws ec2 describe-network-interfaces --network-interface-id $eni --query 'NetworkInterfaces[0].Attachment.AttachmentId' --output text)
        if [ -n "$attachment" ]; then
            aws ec2 detach-network-interface --attachment-id $attachment
        fi
        aws ec2 delete-network-interface --network-interface-id $eni
    done
fi

# Check and delete NAT gateways
nat_gateways=$(aws ec2 describe-nat-gateways --filter "Name=vpc-id,Values=$VPC_ID" --query "NatGateways[].NatGatewayId" --output text)
if [ -n "$nat_gateways" ]; then
    for natgw in $nat_gateways; do
        aws ec2 delete-nat-gateway --nat-gateway-id $natgw
        aws ec2 wait nat-gateway-deleted --nat-gateway-id $natgw
    done
fi

# Check and release EIPs associated with the VPC
eips=$(aws ec2 describe-addresses --region $REGION --query "Addresses[?AssociationId!=null].AllocationId" --output text)
if [ -n "$eips" ]; then
    for eip in $eips; do
        aws ec2 release-address --allocation-id $eip
    done
fi

# Attempt to delete the VPC
aws ec2 delete-vpc --vpc-id $VPC_ID
echo "Attempted to delete VPC $VPC_ID."
