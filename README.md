# AWS Inventory Script

This Python script collects inventory information for various AWS resources, including:

- EC2 Instances
- RDS Instances
- S3 Buckets
- Lambda Functions

The script retrieves and prints the details of these resources in the AWS account using the `boto3` library.

---

## 🚀 Features

- Fetches detailed inventory for:
  - **EC2 Instances**: Instance ID, type, state, IP addresses, tags, and more.
  - **RDS Instances**: DB identifier, engine version, status, and endpoint.
  - **S3 Buckets**: Bucket names and creation dates.
  - **Lambda Functions**: Function names, runtimes, last modified timestamps, and code sizes.
- Handles pagination for large inventories.
- Includes error handling and logging for robust performance.
- Modular design for easy customization and extension.

---

## 🛠 Requirements

- Python 3.7+
- AWS CLI configured with appropriate permissions
- `boto3` library

---

## 🔧 Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/raydnel/aws_inventory_tool.git
   cd aws-inventory-script
   
2. Install dependencies:

`pip install boto3`

3. Configure AWS credentials: Ensure you have configured the AWS CLI with valid credentials or set up the required environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`).

`aws configure`

---

## 🏃‍♂️ Usage

Run the script using:

`python aws_inventory.py`

The script will output the inventory for each service in the console, formatted for readability.

---

## 🛡 Permissions
Ensure the AWS credentials used have the following permissions for successful execution:

EC2: `ec2:DescribeInstances`
RDS: `rds:DescribeDBInstances`
S3: `s3:ListAllMyBuckets`
Lambda: `lambda:ListFunctions`

---
## ✨ Customization
You can extend the script to include other AWS services or save the output to a file (e.g., JSON or CSV). For example, to save inventory to a JSON file:

python
Copy code
import json

`with open('ec2_inventory.json', 'w') as f:`

   `json.dump(ec2_inventory, f, indent=4)`

---

## 📋 Example Output

Here’s an example of what the output looks like:

## EC2 Instances Inventory

   ```bash
{'InstanceId': 'i-0abc123def456ghi7', 'InstanceType': 't2.micro', 'LaunchTime': '2023-11-21 10:15:42', 'State': 'running', 'PrivateIpAddress': '10.0.0.1', 'PublicIpAddress': '54.210.123.45', 'Name': 'WebServer1'}
{'InstanceId': 'i-0xyz890jkl123mno4', 'InstanceType': 't2.small', 'LaunchTime': '2023-10-15 08:30:12', 'State': 'stopped', 'PrivateIpAddress': '10.0.0.2', 'PublicIpAddress': 'N/A', 'Name': 'DatabaseServer'}
