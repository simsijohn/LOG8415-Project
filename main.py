# main.py

import sys
import boto3
import os
import json
import logging
from botocore.exceptions import ClientError
import paramiko

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler()]
)

# Suppress verbose logs from boto3, botocore, and paramiko
logging.getLogger("boto3").setLevel(logging.WARNING)
logging.getLogger("botocore").setLevel(logging.WARNING)
logging.getLogger("paramiko").setLevel(logging.WARNING)


def get_key_pair(ec2_client):
    key_name = "final"
    try:
        ec2_client.describe_key_pairs(KeyNames=[key_name])
        logging.info(f"Key Pair '{key_name}' already exists. Using the existing key.")
        return key_name
    except ClientError as e:
        if 'InvalidKeyPair.NotFound' in str(e):
            response = ec2_client.create_key_pair(KeyName=key_name)
            private_key = response['KeyMaterial']
            key_file_path = os.path.expanduser(f'~/.aws/{key_name}.pem')
            with open(key_file_path, 'w') as file:
                file.write(private_key)
            os.chmod(key_file_path, 0o400)
            logging.info(f"Created and using Key Pair: '{key_name}'")
            return key_name
        else:
            logging.error(f"Error retrieving key pairs: {e}")
            raise


def get_vpc_id(ec2_client):
    response = ec2_client.describe_vpcs()
    vpc_id = response['Vpcs'][0]['VpcId']
    logging.info(f"Using VPC ID: {vpc_id}")
    return vpc_id


def create_security_group(ec2_client, vpc_id, group_name, description, allow_inbound=True, source_group_id=None):
    try:
        response = ec2_client.describe_security_groups(
            Filters=[
                {'Name': 'group-name', 'Values': [group_name]},
                {'Name': 'vpc-id', 'Values': [vpc_id]}
            ]
        )
        if response['SecurityGroups']:
            security_group_id = response['SecurityGroups'][0]['GroupId']
            logging.info(f"Security Group '{group_name}' already exists with ID: {security_group_id}")
            return security_group_id

        response = ec2_client.create_security_group(
            GroupName=group_name,
            Description=description,
            VpcId=vpc_id
        )
        security_group_id = response['GroupId']
        logging.info(f"Created Security Group '{group_name}' with ID: {security_group_id}")

        if allow_inbound:
            ec2_client.authorize_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=[
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    },
                    # Add other ports as needed
                ]
            )
            logging.info(f"Ingress rules added to Security Group '{group_name}'")
        else:
            if source_group_id:
                ec2_client.authorize_security_group_ingress(
                    GroupId=security_group_id,
                    IpPermissions=[
                        {
                            'IpProtocol': 'tcp',
                            'FromPort': 22,
                            'ToPort': 22,
                            'UserIdGroupPairs': [{'GroupId': source_group_id}]
                        },
                        # Add other ports as needed
                    ]
                )
                logging.info(f"Ingress rules with source group '{source_group_id}' added to Security Group '{group_name}'")

        return security_group_id
    except ClientError as e:
        logging.error(f"Error creating security group '{group_name}': {e}")
        raise


def get_subnet(ec2_client, vpc_id):
    response = ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    subnet_id = response['Subnets'][0]['SubnetId']
    logging.info(f"Using Subnet ID: {subnet_id}")
    return subnet_id


def transfer_file(instance_ip, key_file_path, files):
    """
    Transfers files to the specified instance.
    Args:
        instance_ip: Public IP of the instance.
        key_file_path: Path to the key file.
        files: A dictionary of local file paths to remote file paths.
    """
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(instance_ip, username='ubuntu', key_filename=key_file_path)
        sftp = ssh_client.open_sftp()
        for local_file, remote_path in files.items():
            sftp.put(local_file, remote_path)
            logging.info(f"Transferred '{local_file}' to '{instance_ip}:{remote_path}'")
        sftp.close()
        ssh_client.close()
        logging.info(f"Files successfully transferred to {instance_ip}")
    except Exception as e:
        logging.error(f"Error transferring files to {instance_ip}: {e}")


def execute_remote_command(instance_ip, key_file_path, command):
    """
    Executes a remote command on the specified instance via SSH.
    Args:
        instance_ip: Public IP of the instance.
        key_file_path: Path to the SSH key file.
        command: The command to execute.
    """
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(instance_ip, username='ubuntu', key_filename=key_file_path)
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()
        if output:
            logging.info(f"Output from '{instance_ip}': {output}")
        if error:
            logging.error(f"Error from '{instance_ip}': {error}")
        ssh_client.close()
        logging.info(f"Executed command on '{instance_ip}': {command}")
    except Exception as e:
        logging.error(f"Failed to execute command on '{instance_ip}': {e}")


def launch_instance(ec2_client, image_id, instance_type, key_name, security_group_id, subnet_id, user_data, name):
    response = ec2_client.run_instances(
        ImageId=image_id,
        InstanceType=instance_type,
        KeyName=key_name,
        SecurityGroupIds=[security_group_id],
        SubnetId=subnet_id,
        UserData=user_data,
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[{
            'ResourceType': 'instance',
            'Tags': [{'Key': 'Name', 'Value': name}]
        }]
    )
    instance_id = response['Instances'][0]['InstanceId']
    instance = boto3.resource('ec2').Instance(instance_id)
    logging.info(f"Launching instance '{name}' with ID: {instance_id}")
    instance.wait_until_running()
    instance.reload()
    logging.info(f"Instance '{name}' is running with Public IP: {instance.public_ip_address}")
    return instance


def transfer_master_status(manager_instance, key_name):
    """
    Connects to the Manager instance via SSH and retrieves the current master status.

    Args:
        manager_instance: The EC2 instance object of the Manager.
        key_name: The name of the SSH key pair.

    Returns:
        tuple: (MASTER_LOG_FILE, MASTER_LOG_POS)
    """
    key_file_path = os.path.expanduser(f'~/.aws/{key_name}.pem')
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # Connect using the private IP for security
        ssh.connect(manager_instance.private_ip_address, username='ubuntu', key_filename=key_file_path, timeout=30)

        # Execute the SHOW MASTER STATUS command
        command = 'mysql -u root -p123 -e "SHOW MASTER STATUS;"'
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()
        ssh.close()

        if error:
            logging.error(f"Error retrieving master status: {error}")
            raise Exception(f"Error retrieving master status: {error}")

        lines = output.strip().split('\n')
        if len(lines) < 2:
            logging.error("Master status output is incomplete.")
            raise Exception("Master status output is incomplete.")

        master_log_file = lines[1].split()[0]
        master_log_pos = lines[1].split()[1]

        logging.info(f"Master Log File: {master_log_file}")
        logging.info(f"Master Log Position: {master_log_pos}")

        return master_log_file, master_log_pos
    except Exception as e:
        logging.error(f"Failed to retrieve master status: {e}")
        raise


def launch_instance_worker(ec2_client, image_id, instance_type, key_name, security_group_id, subnet_id, name, master_log_file, master_log_pos, manager_instance):
    """
    Launches a Worker (Slave) EC2 instance configured for MySQL replication.

    Args:
        ec2_client: Boto3 EC2 client.
        image_id: AMI ID.
        instance_type: EC2 instance type.
        key_name: SSH key pair name.
        security_group_id: Security group ID.
        subnet_id: Subnet ID.
        name: Name tag for the instance.
        master_log_file: MASTER_LOG_FILE from Manager.
        master_log_pos: MASTER_LOG_POS from Manager.
        manager_instance: The EC2 instance object of the Manager.

    Returns:
        instance: The launched EC2 instance object.
    """
    # Format the worker_user_data with actual variables
    worker_user_data = (r"""#!/bin/bash
set -x
exec > /var/log/user-data.log 2>&1

echo "===== Starting Worker User Data Script ====="

# ==========================
# Configuration Variables
# ==========================

MYSQL_ROOT_PASSWORD="{MYSQL_ROOT_PASSWORD}"
REPLICATION_USER="{REPLICATION_USER}"
REPLICATION_PASSWORD="{REPLICATION_PASSWORD}"

# Manager Instance Details
MANAGER_PRIVATE_IP="{MANAGER_PRIVATE_IP}"

# Master Log File and Position
MASTER_LOG_FILE="{MASTER_LOG_FILE}"
MASTER_LOG_POS={MASTER_LOG_POS}

# ==========================
# System Update & Upgrade
# ==========================

echo "Updating and upgrading the system..."
apt-get update -y
apt-get upgrade -y

# ==========================
# Install MySQL Server
# ==========================

echo "Installing MySQL server..."
apt-get install mysql-server -y

# ==========================
# Secure MySQL Installation
# ==========================

echo "Securing MySQL installation..."

# Change root password and authentication method
mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '${MYSQL_ROOT_PASSWORD}';"

# Remove anonymous users
mysql -e "DELETE FROM mysql.user WHERE User='';"

# Disallow root remote login
mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '${MYSQL_ROOT_PASSWORD}';"

# Remove test database
mysql -e "DROP DATABASE IF EXISTS test;"
mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"

# Reload privilege tables
mysql -e "FLUSH PRIVILEGES;"

# ==========================
# Configure MySQL for Replication
# ==========================

echo "Configuring MySQL for replication..."

# Backup existing configuration
cp /etc/mysql/mysql.conf.d/mysqld.cnf /etc/mysql/mysql.conf.d/mysqld.cnf.bak

# Dynamically assign server-id based on private IP
echo "Determining server-id dynamically based on private IP..."
PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
# Extract the last octet of the IP and add 2 to assign server-id
LAST_OCTET=$(echo $PRIVATE_IP | awk -F. '{print $4}')
SERVER_ID=$((LAST_OCTET + 2))

echo "Assigned server-id=${SERVER_ID}"

# Remove any existing server-id from configuration
sed -i '/server-id/d' /etc/mysql/mysql.conf.d/mysqld.cnf

# Append replication settings with dynamic server-id
bash -c "echo 'server-id=${SERVER_ID}' >> /etc/mysql/mysql.conf.d/mysqld.cnf"
bash -c "echo 'relay_log=/var/log/mysql/mysql-relay-bin.log' >> /etc/mysql/mysql.conf.d/mysqld.cnf"
bash -c "echo 'relay_log_index=/var/log/mysql/mysql-relay-bin.index' >> /etc/mysql/mysql.conf.d/mysqld.cnf"
bash -c "echo 'log_bin=/var/log/mysql/mysql-bin.log' >> /etc/mysql/mysql.conf.d/mysqld.cnf"
bash -c "echo 'binlog_do_db=sakila' >> /etc/mysql/mysql.conf.d/mysqld.cnf"
bash -c "echo 'bind-address=0.0.0.0' >> /etc/mysql/mysql.conf.d/mysqld.cnf"

# Restart MySQL to apply changes
echo "Restarting MySQL service..."
systemctl restart mysql

# Verify MySQL service status
if systemctl is-active --quiet mysql; then
    echo "MySQL service restarted successfully."
else
    echo "MySQL service failed to restart."
    exit 1
fi

# ==========================
# Configure Replication
# ==========================

echo "Configuring replication settings..."

# Wait until MySQL is ready on the Worker
until mysqladmin ping -u root -p"{MYSQL_ROOT_PASSWORD}" --silent; do
    echo "Waiting for MySQL service to be available..."
    sleep 5
done

# Configure the Slave to connect to the Master
echo "Setting up replication to master at {MANAGER_PRIVATE_IP}..."
mysql -u root -p"{MYSQL_ROOT_PASSWORD}" -e "
CHANGE MASTER TO 
    MASTER_HOST='{MANAGER_PRIVATE_IP}', 
    MASTER_USER='{REPLICATION_USER}', 
    MASTER_PASSWORD='{REPLICATION_PASSWORD}', 
    MASTER_LOG_FILE='{MASTER_LOG_FILE}', 
    MASTER_LOG_POS={MASTER_LOG_POS};
"

# Start the Slave replication process
echo "Starting slave replication..."
mysql -u root -p"{MYSQL_ROOT_PASSWORD}" -e "START SLAVE;"

# ==========================
# Verify Replication Status
# ==========================

echo "Verifying replication status..."
SLAVE_IO_RUNNING=$(mysql -u root -p"{MYSQL_ROOT_PASSWORD}" -e "SHOW SLAVE STATUS\\G" | grep Slave_IO_Running | awk '{{print $2}}')
SLAVE_SQL_RUNNING=$(mysql -u root -p"{MYSQL_ROOT_PASSWORD}" -e "SHOW SLAVE STATUS\\G" | grep Slave_SQL_Running | awk '{{print $2}}')

echo "Slave_IO_Running: ${SLAVE_IO_RUNNING}"
echo "Slave_SQL_Running: ${SLAVE_SQL_RUNNING}"

if [[ "$SLAVE_IO_RUNNING" == "Yes" && "$SLAVE_SQL_RUNNING" == "Yes" ]]; then
    echo "Replication is running successfully."
else
    echo "Replication failed to start."
    exit 1
fi

# ==========================
# Install Sakila Database
# ==========================

echo "Installing Sakila database..."

cd /tmp
wget https://downloads.mysql.com/docs/sakila-db.tar.gz
tar -xvf sakila-db.tar.gz

# Import Sakila schema
echo "Importing Sakila schema..."
mysql -u root -p"{MYSQL_ROOT_PASSWORD}" < /tmp/sakila-db/sakila-schema.sql

# Import Sakila data
echo "Importing Sakila data..."
mysql -u root -p"{MYSQL_ROOT_PASSWORD}" < /tmp/sakila-db/sakila-data.sql

# ==========================
# Firewall Configuration (Optional)
# ==========================

# Uncomment the following lines if you want to enable UFW and allow MySQL traffic from Manager
# echo "Configuring UFW firewall..."
# ufw allow 22/tcp
# ufw allow from {MANAGER_PRIVATE_IP} to any port 3306
# ufw --force enable

# ==========================
# Cleanup
# ==========================

echo "Cleaning up temporary files..."
rm -rf /tmp/sakila-db.tar.gz /tmp/sakila-db

echo "===== Worker User Data Script Completed ====="
""").format(
        MYSQL_ROOT_PASSWORD="123",
        REPLICATION_USER="replicator",
        REPLICATION_PASSWORD="123",
        MANAGER_PRIVATE_IP=manager_instance.private_ip_address,
        MASTER_LOG_FILE=master_log_file,
        MASTER_LOG_POS=master_log_pos
    )

    # Launch the Worker instance with formatted user_data
    worker_instance = launch_instance(
        ec2_client,
        image_id,
        instance_type,
        key_name,
        security_group_id,
        subnet_id,
        worker_user_data.strip(),
        name
    )
    return worker_instance


def update_config_file(manager_ip, worker_ips, proxy_ip, gatekeeper_ip, trusted_host_ip):
    config = {
        "manager": {"ip": manager_ip, "port": "3306", "status": "free"},
        "workers": [
            {
                "name": f"worker{i+1}",
                "ip": ip,
                "port": str(3307 + i),
                "status": "free"
            } for i, ip in enumerate(worker_ips)
        ],
        "proxy": {"ip": proxy_ip, "port": "5000"},
        "gatekeeper": {
            "ip": gatekeeper_ip,
            "port": "6000",
            "allowed_services": ["proxy", "manager", "workers"],
            "trusted_host_ip": trusted_host_ip
        }
    }
    config_file_path = os.path.join(os.path.dirname(__file__), "test.json")
    with open(config_file_path, "w") as f:
        json.dump(config, f, indent=4)
    logging.info(f"Configuration updated in {config_file_path}")


def verify_replication(worker_instance, key_name):
    key_file_path = os.path.expanduser(f'~/.aws/{key_name}.pem')
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(worker_instance.private_ip_address, username='ubuntu', key_filename=key_file_path, timeout=30)

        # Execute the SHOW SLAVE STATUS command
        command = 'mysql -u root -p123 -e "SHOW SLAVE STATUS\\G"'
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()
        ssh.close()

        if error:
            logging.error(f"Error verifying replication on Worker {worker_instance.id}: {error}")
            return False

        slave_io = False
        slave_sql = False

        for line in output.split('\n'):
            if "Slave_IO_Running:" in line:
                slave_io = line.split(':')[-1].strip()
            if "Slave_SQL_Running:" in line:
                slave_sql = line.split(':')[-1].strip()

        if slave_io == "Yes" and slave_sql == "Yes":
            logging.info(f"Replication on Worker {worker_instance.id} is running successfully.")
            return True
        else:
            logging.error(f"Replication on Worker {worker_instance.id} is not running correctly.")
            return False
    except Exception as e:
        logging.error(f"Failed to verify replication on Worker {worker_instance.id}: {e}")
        return False


def main():
    try:
        logging.info("Initializing EC2 client...")
        ec2_client = boto3.client('ec2')
        image_id = 'ami-0e86e20dae9224db8'  # Replace with a valid AMI ID for your region

        # Step 1: Setup key pair and VPC
        logging.info("Setting up key pair...")
        key_name = get_key_pair(ec2_client)
        logging.info("Retrieving VPC ID...")
        vpc_id = get_vpc_id(ec2_client)
        logging.info("Retrieving Subnet ID...")
        subnet_id = get_subnet(ec2_client, vpc_id)

        # Create Security Groups
        logging.info("Creating public and private security groups...")
        public_security_group_id = create_security_group(
            ec2_client, vpc_id, "public-security-group", "Public Access Group"
        )
        private_security_group_id = create_security_group(
            ec2_client, vpc_id, "private-security-group", "Private Access Group",
            allow_inbound=False, source_group_id=public_security_group_id
        )

        # Step 2: Define User Data Scripts
        logging.info("Defining user data scripts...")

        # Manager User Data Script
        manager_user_data = (r"""#!/bin/bash
set -x
exec > /var/log/user-data.log 2>&1

echo "===== Starting Manager User Data Script ====="

# ==========================
# Configuration Variables
# ==========================

MYSQL_ROOT_PASSWORD="123"
REPLICATION_USER="replicator"
REPLICATION_PASSWORD="123"

# ==========================
# System Update & Upgrade
# ==========================

echo "Updating and upgrading the system..."
apt-get update -y
apt-get upgrade -y

# ==========================
# Install MySQL Server
# ==========================

echo "Installing MySQL server..."
apt-get install mysql-server -y

# ==========================
# Secure MySQL Installation
# ==========================

echo "Securing MySQL installation..."

# Change root password and authentication method
mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '${MYSQL_ROOT_PASSWORD}';"

# Remove anonymous users
mysql -e "DELETE FROM mysql.user WHERE User='';"

# Disallow root remote login
mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '${MYSQL_ROOT_PASSWORD}';"

# Remove test database
mysql -e "DROP DATABASE IF EXISTS test;"
mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"

# Reload privilege tables
mysql -e "FLUSH PRIVILEGES;"

# ==========================
# Configure MySQL for Replication
# ==========================

echo "Configuring MySQL for replication..."

# Backup existing configuration
cp /etc/mysql/mysql.conf.d/mysqld.cnf /etc/mysql/mysql.conf.d/mysqld.cnf.bak

# Append replication settings if not already present
if ! grep -q "# Replication Configuration" /etc/mysql/mysql.conf.d/mysqld.cnf; then
    cat <<EOF >> /etc/mysql/mysql.conf.d/mysqld.cnf

# Replication Configuration
server-id=1
log_bin=/var/log/mysql/mysql-bin.log
binlog_do_db=sakila
EOF
else
    echo "Replication configuration already exists. Skipping append."
fi

# Restart MySQL to apply changes
echo "Restarting MySQL service..."
systemctl restart mysql

# Verify MySQL service status
if systemctl is-active --quiet mysql; then
    echo "MySQL service restarted successfully."
else
    echo "MySQL service failed to restart."
    exit 1
fi

# ==========================
# Create Replication User
# ==========================

echo "Creating replication user..."
mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -e "
CREATE USER '${REPLICATION_USER}'@'%' IDENTIFIED BY '${REPLICATION_PASSWORD}';
GRANT REPLICATION SLAVE ON *.* TO '${REPLICATION_USER}'@'%';
FLUSH PRIVILEGES;
"

# ==========================
# Obtain Master Status
# ==========================

echo "Obtaining Master Status..."
while true; do
    MASTER_STATUS=$(mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -e "SHOW MASTER STATUS;" | grep mysql-bin)
    if [ -n "$MASTER_STATUS" ]; then
        MASTER_LOG_FILE=$(echo $MASTER_STATUS | awk '{print $1}')
        MASTER_LOG_POS=$(echo $MASTER_STATUS | awk '{print $2}')
        break
    fi
    echo "Master status not available yet. Retrying in 5 seconds..."
    sleep 5
done

echo "Master Log File: ${MASTER_LOG_FILE}"
echo "Master Log Position: ${MASTER_LOG_POS}"

# Save Master Status to a file
echo "Master_Log_File: ${MASTER_LOG_FILE}" | tee /var/log/mysql/master_status.log
echo "Master_Log_Pos: ${MASTER_LOG_POS}" | tee -a /var/log/mysql/master_status.log

# ==========================
# Install Sakila Database
# ==========================

echo "Installing Sakila database..."

cd /tmp
wget https://downloads.mysql.com/docs/sakila-db.tar.gz
tar -xvf sakila-db.tar.gz

# Import Sakila schema
echo "Importing Sakila schema..."
mysql -u root -p"${MYSQL_ROOT_PASSWORD}" < /tmp/sakila-db/sakila-schema.sql

# Import Sakila data
echo "Importing Sakila data..."
mysql -u root -p"${MYSQL_ROOT_PASSWORD}" < /tmp/sakila-db/sakila-data.sql

# ==========================
# Firewall Configuration (Optional)
# ==========================

# Uncomment the following lines if you want to enable UFW and allow MySQL traffic from Manager
# echo "Configuring UFW firewall..."
# ufw allow 22/tcp
# ufw allow from 10.0.0.0/16 to any port 3306
# ufw --force enable

# ==========================
# Cleanup
# ==========================

echo "Cleaning up temporary files..."
rm -rf /tmp/sakila-db.tar.gz /tmp/sakila-db

echo "===== Manager User Data Script Completed ====="
""").strip()

        # Step 3: Launch Manager Instance
        logging.info("Launching Manager instance...")
        manager_instance = launch_instance(
            ec2_client, image_id, 't3.medium', key_name, public_security_group_id, subnet_id,
            manager_user_data, "Manager"
        )

        # Step 4: Retrieve Master Status
        logging.info("Retrieving master status from Manager...")
        master_log_file, master_log_pos = transfer_master_status(manager_instance, key_name)

        # Step 5: Launch Worker Instances with dynamic replication parameters
        logging.info("Launching Worker instances...")
        workers = []
        for i in range(2):
            worker_name = f"Worker-{i + 1}"
            worker_instance = launch_instance_worker(
                ec2_client, image_id, 't3.medium', key_name, public_security_group_id, subnet_id,
                worker_name, master_log_file, master_log_pos, manager_instance
            )
            workers.append(worker_instance)

        # Step 6: Launch Proxy, Gatekeeper, and Trusted Host Instances
        logging.info("Launching Proxy instance...")
        proxy_user_data = ("""#!/bin/bash
sudo apt-get update -y
sudo apt-get install -y python3-pip python3-venv
python3 -m venv /home/ubuntu/venv
/home/ubuntu/venv/bin/pip install flask requests
nohup python3 /home/ubuntu/proxy.py &
echo "Proxy setup complete!" >> /home/ubuntu/setup.log
""").strip()
        proxy_instance = launch_instance(
            ec2_client, image_id, 't2.large', key_name, public_security_group_id, subnet_id,
            proxy_user_data, "Proxy"
        )

        logging.info("Launching Gatekeeper instance...")
        gatekeeper_user_data = ("""#!/bin/bash
sudo apt update -y
sudo apt install -y python3-pip python3-venv
python3 -m venv /home/ubuntu/venv
/home/ubuntu/venv/bin/pip install flask
nohup python3 /home/ubuntu/gatekeeper.py &
echo "Gatekeeper setup complete!" >> /home/ubuntu/setup.log
""").strip()
        gatekeeper_instance = launch_instance(
            ec2_client, image_id, 't2.large', key_name, public_security_group_id, subnet_id,
            gatekeeper_user_data, "Gatekeeper"
        )

        logging.info("Launching Trusted Host instance...")
        trusted_host_user_data = ("""#!/bin/bash
sudo apt update -y
sudo apt install -y python3-pip python3-venv
python3 -m venv /home/ubuntu/venv
/home/ubuntu/venv/bin/pip install flask
nohup python3 /home/ubuntu/trustedhost.py &
echo "Trusted Host setup complete!" >> /home/ubuntu/setup.log
""").strip()
        trusted_host_instance = launch_instance(
            ec2_client, image_id, 't2.large', key_name, public_security_group_id, subnet_id,
            trusted_host_user_data, "TrustedHost"
        )

        # Step 7: Retrieve IPs
        logging.info("Retrieving public IPs of launched instances...")
        manager_ip = manager_instance.public_ip_address
        worker_ips = [worker.public_ip_address for worker in workers]
        proxy_ip = proxy_instance.public_ip_address
        gatekeeper_ip = gatekeeper_instance.public_ip_address
        trusted_host_ip = trusted_host_instance.public_ip_address

        # Step 8: Update Configuration File
        logging.info("Updating configuration file...")
        update_config_file(manager_ip, worker_ips, proxy_ip, gatekeeper_ip, trusted_host_ip)

        # Step 9: Verify Replication on Workers
        logging.info("Verifying replication status on Worker instances...")
        for worker in workers:
            success = verify_replication(worker, key_name)
            if not success:
                logging.error(f"Replication verification failed on Worker {worker.id}.")

        # Step 10: Transfer Files to Instances
        key_file_path = os.path.expanduser(f'~/.aws/{key_name}.pem')
        logging.info("Transferring files to instances...")
        transfer_file(manager_ip, key_file_path, {"test.json": "/home/ubuntu/test.json"})
        for worker_ip in worker_ips:
            transfer_file(worker_ip, key_file_path, {
                "test.json": "/home/ubuntu/test.json",
                "worker.py": "/home/ubuntu/worker.py"
            })
        transfer_file(proxy_ip, key_file_path, {
            "proxy.py": "/home/ubuntu/proxy.py",
            "test.json": "/home/ubuntu/test.json"
        })
        transfer_file(gatekeeper_ip, key_file_path, {
            "gatekeeper.py": "/home/ubuntu/gatekeeper.py"
        })
        transfer_file(trusted_host_ip, key_file_path, {
            "trustedhost.py": "/home/ubuntu/trustedhost.py"
        })

        # Step 11: Execute Transferred Scripts on Instances
        logging.info("Executing transferred scripts on instances...")
        # Define the mapping of scripts to execute on each instance
        script_execution_commands = {
            proxy_ip: "python3 /home/ubuntu/proxy.py &",
            gatekeeper_ip: "python3 /home/ubuntu/gatekeeper.py &",
            trusted_host_ip: "python3 /home/ubuntu/trustedhost.py &"
        }
        for ip, command in script_execution_commands.items():
            execute_remote_command(ip, key_file_path, command)

        # Optionally, execute worker scripts if applicable
        for worker_ip in worker_ips:
            execute_remote_command(worker_ip, key_file_path, "python3 /home/ubuntu/worker.py &")

        logging.info("Deployment completed successfully.")

    except Exception as e:
        logging.error(f"Error during deployment: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()