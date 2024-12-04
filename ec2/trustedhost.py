# ec2/trustedhost.py

import paramiko
from botocore.exceptions import ClientError

def setup_trusted_host(instance_ip, key_file_path):
    """
    SSH into the Trusted Host instance and deploy the Trusted Host application.
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print(f"Connecting to Trusted Host instance at {instance_ip} via SSH...")
        ssh.connect(hostname=instance_ip, username='ubuntu', key_filename=key_file_path, timeout=60)
        print("Connected to Trusted Host instance.")

        # Define the setup commands
        commands = [
            "sudo apt-get update -y",
            "sudo apt-get install -y git",
            "git clone https://github.com/your-repo/trustedhost.git /home/ubuntu/trustedhost",  # Replace with your repo
            "cd /home/ubuntu/trustedhost",
            "python3 -m venv venv",
            "source venv/bin/activate",
            "pip install -r requirements.txt",
            "nohup python app.py &"
        ]

        for cmd in commands:
            print(f"Executing command: {cmd}")
            stdin, stdout, stderr = ssh.exec_command(cmd)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0:
                print(f"Command executed successfully: {cmd}")
            else:
                error = stderr.read().decode()
                print(f"Error executing command '{cmd}': {error}")
                raise Exception(f"Command '{cmd}' failed with error: {error}")

        print("Trusted Host setup completed successfully.")

    except Exception as e:
        print(f"Failed to setup Trusted Host instance '{instance_ip}': {e}")
        raise
    finally:
        ssh.close()