# ec2/ec2_manager.py

import boto3
from botocore.exceptions import ClientError


def create_security_group(ec2_client, vpc_id, group_name, description, allow_inbound=True, source_group_id=None):
    """
    Creates a security group with specified parameters.
    If allow_inbound is True, adds SSH (port 22) and MySQL (port 3306) ingress rules.
    """
    try:
        response = ec2_client.create_security_group(
            GroupName=group_name,
            Description=description,
            VpcId=vpc_id
        )
        security_group_id = response['GroupId']
        print(f"Created security group '{group_name}' with ID: {security_group_id}")

        if allow_inbound:
            # Ingress rules
            ec2_client.authorize_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=[
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    },
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 3306,
                        'ToPort': 3306,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    }
                ]
            )
            print(f"Ingress rules added to security group '{group_name}'")

        return security_group_id
    except ClientError as e:
        print(f"Error creating security group '{group_name}': {e}")
        raise


def launch_instance(ec2_client, image_id, instance_type, key_name, security_group_id, subnet_id, user_data,
                    instance_role):
    """
    Launches an EC2 instance with specified parameters.
    """
    try:
        response = ec2_client.run_instances(
            ImageId=image_id,
            InstanceType=instance_type,
            KeyName=key_name,
            SecurityGroupIds=[security_group_id],
            SubnetId=subnet_id,
            UserData=user_data,
            MinCount=1,
            MaxCount=1,
            TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': [
                        {
                            'Key': 'Role',
                            'Value': instance_role
                        }
                    ]
                }
            ]
        )
        instance = response['Instances'][0]
        instance_id = instance['InstanceId']
        print(f"Launched {instance_role} instance with ID: {instance_id}")
        return instance
    except ClientError as e:
        print(f"Error launching {instance_role} instance: {e}")
        raise


def get_vpc_id(ec2_client):
    """
    Retrieves the default VPC ID.
    """
    try:
        response = ec2_client.describe_vpcs(
            Filters=[{'Name': 'isDefault', 'Values': ['true']}]
        )
        vpc_id = response['Vpcs'][0]['VpcId']
        print(f"Default VPC ID: {vpc_id}")
        return vpc_id
    except ClientError as e:
        print(f"Error retrieving VPC ID: {e}")
        raise


def get_subnet(ec2_client, vpc_id):
    """
    Retrieves the first available subnet ID in the specified VPC.
    """
    try:
        response = ec2_client.describe_subnets(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
        )
        subnet_id = response['Subnets'][0]['SubnetId']
        print(f"Selected Subnet ID: {subnet_id}")
        return subnet_id
    except ClientError as e:
        print(f"Error retrieving Subnet ID: {e}")
        raise