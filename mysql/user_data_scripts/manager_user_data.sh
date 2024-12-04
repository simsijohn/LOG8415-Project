#!/bin/bash
# mysql/user_data_scripts/manager_user_data.sh

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

# Configure MySQL for Replication
sudo mysql -u root -p123 -e "GRANT REPLICATION SLAVE ON *.* TO 'replica_user'@'%' IDENTIFIED BY 'replica_pass';"
sudo mysql -u root -p123 -e "FLUSH PRIVILEGES;"

# Enable Binary Logging and Configure Server ID
sudo sed -i '/^\[mysqld\]/a server-id=1\nlog