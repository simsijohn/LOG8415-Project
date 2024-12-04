# mysql/mysql_setup.py

import paramiko
import time
import os


def execute_user_data_script(instance_ip, key_file_path, script_path, replacements=None):
    """
    Executes a user data script on the given EC2 instance via SSH.
    If replacements are provided, replaces placeholders in the script before execution.
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(hostname=instance_ip, username='ubuntu', key_filename=key_file_path, timeout=60)
        print(f"Connected to instance at {instance_ip} via SSH.")

        # Read and replace placeholders in the script
        with open(script_path, 'r') as script_file:
            script_content = script_file.read()
            if replacements:
                for key, value in replacements.items():
                    placeholder = f"{{{{{key}}}}}"
                    script_content = script_content.replace(placeholder, value)

        # Upload the script to the instance
        sftp = ssh.open_sftp()
        remote_script_path = f"/home/ubuntu/{os.path.basename(script_path)}"
        sftp.put(script_path, remote_script_path)
        sftp.close()
        print(f"Uploaded user data script to '{remote_script_path}'.")

        # Make the script executable
        ssh.exec_command(f"chmod +x {remote_script_path}")

        # Execute the script
        stdin, stdout, stderr = ssh.exec_command(f"bash {remote_script_path}")

        # Wait for the script to complete
        exit_status = stdout.channel.recv_exit_status()
        if exit_status == 0:
            print(f"User data script executed successfully on instance '{instance_ip}'.")
        else:
            error = stderr.read().decode()
            print(f"Error executing user data script on instance '{instance_ip}': {error}")
            raise Exception(f"User data script failed with error: {error}")

    except Exception as e:
        print(f"Failed to execute user data script on instance '{instance_ip}': {e}")
        raise
    finally:
        ssh.close()


def retrieve_master_status(instance_ip, key_file_path):
    """
    Retrieves the MySQL master log file and position from the Manager instance.
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=instance_ip, username='ubuntu', key_filename=key_file_path, timeout=60)
        print(f"Connected to Manager instance at {instance_ip} via SSH.")

        command = "mysql -u root -p123 -e 'SHOW MASTER STATUS;'"
        stdin, stdout, stderr = ssh.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status == 0:
            output = stdout.read().decode()
            lines = output.strip().split('\n')
            if len(lines) >= 2:
                columns = lines[0].split('\t')
                values = lines[1].split('\t')
                master_status = dict(zip(columns, values))
                master_log_file = master_status.get('File')
                master_log_pos = master_status.get('Position')
                print(f"Master Log File: {master_log_file}, Master Log Position: {master_log_pos}")
                return master_log_file, master_log_pos
            else:
                print("No master status found.")
                raise Exception("Master status retrieval failed.")
        else:
            error = stderr.read().decode()
            print(f"Error retrieving master status: {error}")
            raise Exception(f"Master status retrieval failed with error: {error}")
    except Exception as e:
        print(f"Failed to retrieve master status from Manager: {e}")
        raise
    finally:
        ssh.close()


def verify_replication(instance_ip, key_file_path):
    """
    Verifies MySQL replication status on a Worker instance.
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=instance_ip, username='ubuntu', key_filename=key_file_path, timeout=60)
        print(f"Connected to Worker instance at {instance_ip} via SSH.")

        command = "mysql -u root -p123 -e 'SHOW SLAVE STATUS\G;'"
        stdin, stdout, stderr = ssh.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status == 0:
            output = stdout.read().decode()
            if "Slave_IO_Running: Yes" in output and "Slave_SQL_Running: Yes" in output:
                print(f"Replication is running successfully on Worker '{instance_ip}'.")
                return True
            else:
                print(f"Replication is not running correctly on Worker '{instance_ip}'.")
                return False
        else:
            error = stderr.read().decode()
            print(f"Error verifying replication on Worker '{instance_ip}': {error}")
            return False
    except Exception as e:
        print(f"Failed to verify replication on Worker '{instance_ip}': {e}")
        return False
    finally:
        ssh.close()