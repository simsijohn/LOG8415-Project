import paramiko
from botocore.exceptions import ClientError

def execute_user_data_script(instance_ip, key_file_path, script_path, replacements=None):
    """
    SSH into the instance and execute the user data script.
    Replace placeholders in the script with actual values.
    """
    print(f"Connecting to instance at {instance_ip} to execute user data script...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(hostname=instance_ip, username='ubuntu', key_filename=key_file_path, timeout=60)
        print(f"Connected to instance '{instance_ip}'. Executing user data script.")

        # Read the script content
        with open(script_path, 'r') as file:
            script_content = file.read()

        # Replace placeholders if any
        if replacements:
            for key, value in replacements.items():
                placeholder = f"{{{{{key}}}}}"  # e.g., {{manager_ip}}
                script_content = script_content.replace(placeholder, value)

        # Upload the modified script to the instance
        sftp = ssh.open_sftp()
        remote_script_path = "/home/ubuntu/setup_mysql.sh"
        with sftp.file(remote_script_path, 'w') as remote_file:
            remote_file.write(script_content)
        sftp.chmod(remote_script_path, 0o755)
        sftp.close()
        print(f"Uploaded user data script to '{remote_script_path}'.")

        # Execute the script
        stdin, stdout, stderr = ssh.exec_command(f"bash {remote_script_path}")
        exit_status = stdout.channel.recv_exit_status()  # Wait for command to complete

        output = stdout.read().decode()
        error = stderr.read().decode()

        if output:
            print(f"User data script output:\n{output}")
        if error:
            print(f"User data script error:\n{error}")
            raise Exception(f"Error executing user data script: {error}")

        print("User data script executed successfully.")

    except Exception as e:
        print(f"Failed to execute user data script on instance '{instance_ip}': {e}")
        raise
    finally:
        ssh.close()


def retrieve_master_status(manager_ip, key_file_path):
    """
    SSH into the Manager instance and retrieve MySQL master status.
    Returns the master log file and position.
    """
    print(f"Connecting to Manager instance at {manager_ip} via SSH...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(hostname=manager_ip, username='ubuntu', key_filename=key_file_path, timeout=60)
        print("Connected to Manager instance.")

        # Execute MySQL command to get master status
        stdin, stdout, stderr = ssh.exec_command("mysql -u root -p123 -e 'SHOW MASTER STATUS;'")
        output = stdout.read().decode()
        error = stderr.read().decode()

        if error:
            print(f"Error retrieving master status: {error}")
            raise Exception(f"Error retrieving master status: {error}")

        lines = output.strip().split('\n')
        if len(lines) < 2:
            print("Master status not available.")
            raise Exception("Master status not available.")

        master_log_file, master_log_pos = lines[1].split('\t')[:2]
        print(f"Master Log File: {master_log_file}, Master Log Position: {master_log_pos}")
        return master_log_file, master_log_pos

    except Exception as e:
        print(f"Failed to retrieve master status via SSH: {e}")
        raise
    finally:
        ssh.close()


def verify_replication(worker_ip, key_file_path):
    """
    SSH into the Worker instance and verify replication status.
    Returns True if replication is running, False otherwise.
    """
    print(f"Connecting to Worker instance at {worker_ip} via SSH to verify replication...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(hostname=worker_ip, username='ubuntu', key_filename=key_file_path, timeout=60)
        print("Connected to Worker instance.")

        # Execute MySQL command to check replication status
        cmd = "mysql -u root -p123 -e 'SHOW SLAVE STATUS\\G'"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        output = stdout.read().decode()
        error = stderr.read().decode()

        if error:
            print(f"Error verifying replication status: {error}")
            return False

        slave_io_running = "No"
        slave_sql_running = "No"

        for line in output.split('\n'):
            if "Slave_IO_Running:" in line:
                slave_io_running = line.split(':')[-1].strip()
            if "Slave_SQL_Running:" in line:
                slave_sql_running = line.split(':')[-1].strip()

        print(f"Slave_IO_Running: {slave_io_running}")
        print(f"Slave_SQL_Running: {slave_sql_running}")

        if slave_io_running == "Yes" and slave_sql_running == "Yes":
            print("Replication is running successfully.")
            return True
        else:
            print("Replication failed to start.")
            return False

    except Exception as e:
        print(f"Failed to verify replication via SSH on Worker '{worker_ip}': {e}")
        return False
    finally:
        ssh.close()