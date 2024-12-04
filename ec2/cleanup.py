import boto3
from botocore.exceptions import ClientError


def cleanup_instances(ec2_client, instance_ids):
    """
    Terminates the specified EC2 instances.
    """
    try:
        print("Terminating EC2 instances...")
        ec2_client.terminate_instances(InstanceIds=instance_ids)
        print(f"Termination initiated for instances: {instance_ids}")
    except ClientError as e:
        print(f"Error terminating instances: {e}")
        raise


def delete_security_groups(ec2_client, group_ids):
    """
    Deletes the specified security groups one by one.
    """
    for group_id in group_ids:
        try:
            print(f"Deleting Security Group: {group_id}")
            ec2_client.delete_security_group(GroupId=group_id)
            print(f"Deleted security group: {group_id}")
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'DependencyViolation':
                print(f"Cannot delete security group {group_id} as it's in use. Skipping.")
            elif error_code == 'InvalidGroup.NotFound':
                print(f"Security group {group_id} not found. It might have been already deleted.")
            else:
                print(f"Error deleting security group {group_id}: {e}")
                raise


def cleanup_key_pair(ec2_client, key_name):
    """
    Deletes the specified key pair.
    """
    try:
        print(f"Deleting Key Pair: {key_name}")
        ec2_client.delete_key_pair(KeyName=key_name)
        print(f"Deleted key pair: {key_name}")
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'InvalidKeyPair.NotFound':
            print(f"Key pair {key_name} not found. It might have been already deleted.")
        else:
            print(f"Error deleting key pair {key_name}: {e}")
            raise


def main():
    # Initialize EC2 client
    region = 'us-east-1'  # Replace with your AWS region
    ec2_client = boto3.client('ec2', region_name=region)

    # Define instance and security group IDs to clean up
    # Replace these with your actual instance and security group IDs
    instance_ids = [
        'i-0123456789abcdef0',  # Manager
        'i-0fedcba9876543210',  # Worker-1
        'i-0abcde12345fgh6789',  # Worker-2
        'i-0zyxw98765vuts4321',  # Proxy
        'i-0mnop54321qrst0987',  # Gatekeeper-1
        'i-0lkjih65432ponm0987',  # Gatekeeper-2
        'i-0asdf12345ghjk6789'  # TrustedHost
    ]

    security_group_ids = [
        'sg-0123456789abcdef0',  # public-security-group
        'sg-0fedcba9876543210'  # private-security-group
    ]

    key_name = "final"  # Replace with your actual key pair name

    # Step 1: Terminate Instances
    cleanup_instances(ec2_client, instance_ids)

    # Optional: Wait for instances to terminate
    waiter = ec2_client.get_waiter('instance_terminated')
    print("Waiting for instances to terminate...")
    try:
        waiter.wait(InstanceIds=instance_ids)
        print("All instances have been terminated.")
    except ClientError as e:
        print(f"Error waiting for instance termination: {e}")

    # Step 2: Delete Security Groups
    delete_security_groups(ec2_client, security_group_ids)

    # Step 3: Delete Key Pair
    cleanup_key_pair(ec2_client, key_name)

    print("Cleanup process completed successfully.")


if __name__ == "__main__":
    main()