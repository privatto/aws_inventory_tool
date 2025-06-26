# AWS Inventory Script

This Python script collects inventory information for various AWS resources and generates visual analysis (charts) for each resource type. It now includes **automatic generation of bar charts for S3, Route53 Records, and Route53 Zones**, as well as other improvements.

## 🆕 New Features

- **Automatic chart generation for S3 buckets:**
  - Bar chart for bucket count by region
  - Bar chart for bucket size distribution (GB)
  - Bar chart for buckets with size zero
  - Prints total storage and bucket statistics

- **Automatic chart generation for Route53 Records:**
  - Bar chart for top 20 record names
  - Bar chart for record count by TTL
  - Bar chart for record count by type
  - Prints total records, duplicate names, and unique types

- **Automatic chart generation for Route53 Zones:**
  - Bar chart for zone count by region
  - Bar chart for top 20 zone names
  - Bar chart for zone count by Id
  - Bar chart for zone count by PrivateZone (True/False)
  - Bar chart for top 20 ResourceRecordSetCount
  - Prints total zones and duplicate names

- **Each AWS product is identified by filename and processed with its own logic.**
- **Bloco genérico**: For all other products, generates pie charts for relevant columns.

---

## Supported AWS Resources

- EC2 Instances
- RDS Instances
- S3 Buckets (with special charts)
- Lambda Functions
- EKS Clusters
- Spot Instance Requests
- IAM Users
- IAM Roles
- CloudFront Distributions
- DynamoDB Tables
- ELBv2 Load Balancers
- SNS Topics
- SQS Queues
- CloudFormation Stacks
- ECR Repositories
- DocumentDB Clusters
- Redshift Clusters
- ElastiCache Clusters
- EFS File Systems
- FSx File Systems
- Glacier Vaults
- AWS Backup Vaults
- EBS Volumes
- VPCs
- EC2 Security Groups
- EC2 Key Pairs
- ACM Certificates
- Route53 Hosted Zones (with special charts)
- Route53 Records (with special charts)
- Elastic Beanstalk Environments
- Elastic IPs
- KMS Keys
- Secrets Manager Secrets
- SSM Parameters
- Step Functions
- API Gateway APIs
- AppSync APIs
- CodeBuild Projects
- CodePipeline Pipelines
- CodeDeploy Applications
- CloudWatch Alarms
- CloudWatch Log Groups
- Organizations
- Cost Explorer
- WAF WebACLs
- Shield Protections
- SageMaker Notebooks
- Athena Workgroups
- Glue Jobs
- MSK Clusters
- Direct Connect Connections
- Outposts
- Service Catalog Products
- Macie Findings
- GuardDuty Detectors
- Detective Graphs
- Resource Groups
- Resource Tag Editor

---

## 🚀 Features

- Fetches detailed inventory for a wide range of AWS resources (see list above).
- Handles pagination for large inventories.
- Includes error handling and logging for robust performance.
- Modular design for easy customization and extension.
- Saves each resource inventory to a CSV file, prefixed with the AWS account ID.
- **NEW:** Includes a merge utility (`merge.py`) to unify/concatenate CSV files by AWS product.
- **NEW:** Generates charts for S3, Route53 Records, and Route53 Zones automatically.

---

## 🔄 CSV Merge Utility

The script `merge.py` allows you to automatically merge all CSV files in the current directory that correspond to the same AWS product (e.g., all EC2 CSVs, all S3 CSVs, etc.). For each AWS product, it generates a unified CSV file named `<produto>.csv` (e.g., `ec2.csv`, `s3.csv`).

**How it works:**
- Scans the current directory for all `.csv` files.
- Identifies the AWS product in the filename (e.g., `_ec2_`, `_ec2.csv`, `ec2_`, `ec2.csv`).
- Concatenates all files for the same product, even if they have different columns.
- Saves a single CSV file per product with all the data combined.

**Usage:**
```bash
python merge.py
```
After running, you will find one CSV file for each AWS product with all the data unified.

---

## 📊 Chart Generation

After running the inventory and merge scripts, run the analysis script to generate charts:

```bash
python inventory_analysis.py
```
Charts will be saved in the `graficos` directory. Special charts are generated for S3, Route53 Records, and Route53 Zones. For other products, pie charts are generated for relevant columns.

---

## 🛠 Requirements

- Python 3.7+
- AWS CLI configured with appropriate permissions
- `boto3` library
- `matplotlib` and `pandas` libraries

---

## 🔧 Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/privatto/aws_inventory_tool.git
   cd aws_inventory_tool
   ```

2. Install dependencies:

   ```bash
   pip install boto3 matplotlib pandas
   ```

3. Configure AWS credentials: Ensure you have configured the AWS CLI with valid credentials or set up the required environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`).

   See: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html?icmpid=docs_sso_user_portal

   ```bash
   aws configure
   ```

---

## 🏃‍♂️ Usage

Run the inventory script:

```bash
python aws_inventory.py
```

Merge CSVs:

```bash
python merge.py
```

Generate charts:

```bash
python inventory_analysis.py
```

The script will output the inventory for each service in the console and save a CSV file and charts for each resource.

---

## 🛡 Permissions

Ensure the AWS credentials used have the following permissions for successful execution (add more as needed for all resources):

```
ec2:DescribeInstances
ec2:DescribeVpcs
ec2:DescribeSecurityGroups
ec2:DescribeKeyPairs
ec2:DescribeAddresses
ec2:DescribeSpotInstanceRequests
ec2:DescribeVolumes
rds:DescribeDBInstances
s3:ListAllMyBuckets
lambda:ListFunctions
eks:ListClusters
eks:DescribeCluster
iam:ListUsers
iam:ListRoles
cloudfront:ListDistributions
dynamodb:ListTables
dynamodb:DescribeTable
elasticloadbalancing:DescribeLoadBalancers
sns:ListTopics
sqs:ListQueues
cloudformation:DescribeStacks
ecr:DescribeRepositories
docdb:DescribeDBClusters
redshift:DescribeClusters
elasticache:DescribeCacheClusters
elasticfilesystem:DescribeFileSystems
fsx:DescribeFileSystems
glacier:ListVaults
backup:ListBackupVaults
acm:ListCertificates
route53:ListHostedZones
route53:ListResourceRecordSets
elasticbeanstalk:DescribeEnvironments
kms:ListKeys
kms:DescribeKey
secretsmanager:ListSecrets
ssm:DescribeParameters
states:ListStateMachines
apigateway:GetRestApis
appsync:ListGraphqlApis
codebuild:ListProjects
codebuild:BatchGetProjects
codepipeline:ListPipelines
codedeploy:ListApplications
cloudwatch:DescribeAlarms
logs:DescribeLogGroups
organizations:DescribeOrganization
ce:GetCostAndUsage
waf:ListWebACLs
shield:ListProtections
sagemaker:ListNotebookInstances
athena:ListWorkGroups
glue:ListJobs
kafka:ListClusters
directconnect:DescribeConnections
outposts:ListOutposts
servicecatalog:SearchProductsAsAdmin
macie2:ListFindings
guardduty:ListDetectors
detective:ListGraphs
resource-groups:ListGroups
resourcegroupstaggingapi:GetResources
```

---

## ✨ Customization

You can extend the script to include other AWS services or save the output to a file (e.g., JSON or CSV). For example, to save inventory to a JSON file:

```python
import json

with open('ec2_inventory.json', 'w') as f:
    json.dump(ec2_inventory, f, indent=4)
```

---

## 📋 Example Output

Here’s an example of what the output looks like:

### EC2 Instances Inventory

```python
{'InstanceId': 'i-0abc123def456ghi7', 'InstanceType': 't2.micro', 'LaunchTime': '2023-11-21 10:15:42', 'State': 'running', 'PrivateIpAddress': '10.0.0.1', 'PublicIpAddress': '54.210.123.45', 'Name': 'WebServer1'}
{'InstanceId': 'i-0xyz890jkl123mno4', 'InstanceType': 't2.small', 'LaunchTime': '2023-10-15 08:30:12', 'State': 'stopped', 'PrivateIpAddress': '10.0.0.2', 'PublicIpAddress': 'N/A', 'Name': 'DatabaseServer'}
```
