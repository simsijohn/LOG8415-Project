import boto3
from botocore.exceptions import ClientError
import os

def get_ec2_client():
    """
    Initializes and returns a Boto3 EC2 client.
    Assumes AWS credentials are set in environment variables or AWS config files.
    """
    try:
        ec2_client = boto3.client('ec2', region_name='us-east-1')  # Replace with your desired region
        return ec2_client
    except ClientError as e:
        print(f"Error initializing EC2 client: {e}")
        raise