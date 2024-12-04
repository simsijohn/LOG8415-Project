#!/bin/bash
# mysql/user_data_scripts/worker_user_data.sh

# Variables to be replaced
MANAGER_IP="{{manager_ip}}"
MASTER_LOG_FILE="{{master_log_file}}"
MASTER_LOG_POS="{{master_log_pos}}"

# Update and install MySQL
sudo apt-get update -y
sudo apt-get install mysql-server -y

# Secure MySQL Installation
sudo mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '123';"
sudo mysql -e "DELETE FROM mysql.user WHERE User='';"
sudo mysql -e "DROP DATABASE IF EXISTS test;"
sudo mysql -e "FLUSH PRIVILEGES;"

# Install Sakila Database
cd /tmp
wget https://downloads.mysql.com/docs/sakila-db.tar.gz
tar -xvf sakila-db.tar.gz
sudo mysql < /tmp/sakila-db/sakila-schema.sql
sudo mysql < /tmp/sakila-db/sakila-data.sql

# Configure MySQL as Slave
sudo mysql -u root -p123 -e "
CHANGE MASTER TO
    MASTER_HOST='${MANAGER_IP}',
    MASTER_USER='replica_user',
    MASTER_PASSWORD='replica_pass',
    MASTER_LOG_FILE='${MASTER_LOG_FILE}',
    MASTER_LOG_POS=${MASTER_LOG_POS};
START SLAVE;
"

# Enable Server ID and Disable Binary Logging
sudo sed -i '/^\[mysqld\]/a server-id=2\nrelay_log=relay-bin' /etc/mysql/mysql.conf.d/mysqld.cnf
sudo systemctl restart mysql

# Check Slave Status
sudo mysql -u root -p123 -e "SHOW SLAVE STATUS\G;"