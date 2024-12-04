# Cloud Computing TP3 Individual Project

## Overview

This project automates the deployment of a MySQL cluster with replication on AWS EC2 instances. It includes additional components such as Proxy, Gatekeeper, and TrustedHost to manage and monitor the cluster.

## Prerequisites

- **AWS Account:** Ensure you have an AWS account with the necessary permissions to create EC2 instances, security groups, and key pairs.
- **Python 3.x:** Installed on your local machine.
- **AWS CLI:** Installed and configured with your credentials.
- **SSH Key Pair:** Ensure you have an SSH key pair (`final.pem`) stored in `~/.aws/`.

## Setup Instructions

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/Cloud_Computing_TP3_Individual.git
   cd Cloud_Computing_TP3_Individual