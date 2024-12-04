# ec2/transfer_files.py

import subprocess

def transfer_file(instance_ip, key_file_path, files_mapping):
    """
    Transfer files to the specified EC2 instance using SCP.
    files_mapping: dict where key is local file path, value is remote file path.
    """
    for local_file, remote_path in files_mapping.items():
        try:
            scp_command = [
                "scp",
                "-i", key_file_path,
                "-o", "StrictHostKeyChecking=no",
                local_file,
                f"ubuntu@{instance_ip}:{remote_path}"
            ]
            subprocess.run(scp_command, check=True)
            print(f"Transferred '{local_file}' to '{instance_ip}:{remote_path}'.")
        except subprocess.CalledProcessError as e:
            print(f"Error transferring '{local_file}' to '{instance_ip}:{remote_path}': {e}")
            raise