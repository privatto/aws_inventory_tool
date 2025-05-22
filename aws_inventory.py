import boto3
import logging
from botocore.exceptions import ClientError
import csv

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def get_account_and_region(client):
    sts = boto3.client('sts')
    account_id = sts.get_caller_identity()["Account"]
    region = client.meta.region_name
    return account_id, region

def get_ec2_inventory():
    ec2 = boto3.client('ec2')
    account_id, region = get_account_and_region(ec2)
    instances = []
    try:
        paginator = ec2.get_paginator('describe_instances')
        for page in paginator.paginate():
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    instance_info = {
                        "InstanceId": instance["InstanceId"],
                        "InstanceType": instance["InstanceType"],
                        "LaunchTime": instance["LaunchTime"].strftime("%Y-%m-%d %H:%M:%S"),
                        "State": instance["State"]["Name"],
                        "PrivateIpAddress": instance.get("PrivateIpAddress", "N/A"),
                        "PublicIpAddress": instance.get("PublicIpAddress", "N/A"),
                        "Name": next((tag["Value"] for tag in instance.get("Tags", []) if tag["Key"] == "Name"), "N/A"),
                        "AccountId": account_id,
                        "Region": region
                    }
                    instances.append(instance_info)
    except ClientError as e:
        logging.error(f"Error retrieving EC2 instances: {e}")
    return instances

def get_rds_inventory():
    rds = boto3.client('rds')
    account_id, region = get_account_and_region(rds)
    rds_instances = []
    try:
        paginator = rds.get_paginator('describe_db_instances')
        for page in paginator.paginate():
            for instance in page["DBInstances"]:
                rds_instance_info = {
                    "DBInstanceIdentifier": instance["DBInstanceIdentifier"],
                    "Engine": instance["Engine"],
                    "EngineVersion": instance["EngineVersion"],
                    "InstanceCreateTime": instance["InstanceCreateTime"].strftime("%Y-%m-%d %H:%M:%S"),
                    "DBInstanceStatus": instance["DBInstanceStatus"],
                    "Endpoint": instance["Endpoint"]["Address"],
                    "AccountId": account_id,
                    "Region": region
                }
                rds_instances.append(rds_instance_info)
    except ClientError as e:
        logging.error(f"Error retrieving RDS instances: {e}")
    return rds_instances

def get_s3_inventory():
    s3 = boto3.client('s3')
    account_id, region = get_account_and_region(s3)
    s3_buckets = []
    try:
        response = s3.list_buckets()
        for bucket in response["Buckets"]:
            s3_bucket_info = {
                "Name": bucket["Name"],
                "CreationDate": bucket["CreationDate"].strftime("%Y-%m-%d %H:%M:%S"),
                "AccountId": account_id,
                "Region": region
            }
            s3_buckets.append(s3_bucket_info)
    except ClientError as e:
        logging.error(f"Error retrieving S3 buckets: {e}")
    return s3_buckets

def get_lambda_inventory():
    lambda_client = boto3.client('lambda')
    account_id, region = get_account_and_region(lambda_client)
    lambda_functions = []
    try:
        paginator = lambda_client.get_paginator('list_functions')
        for page in paginator.paginate():
            for function in page["Functions"]:
                lambda_function_info = {
                    "FunctionName": function["FunctionName"],
                    "Runtime": function["Runtime"],
                    "LastModified": function["LastModified"],
                    "CodeSize": function["CodeSize"],
                    "AccountId": account_id,
                    "Region": region
                }
                lambda_functions.append(lambda_function_info)
    except ClientError as e:
        logging.error(f"Error retrieving Lambda functions: {e}")
    return lambda_functions

def get_eks_inventory():
    eks = boto3.client('eks')
    account_id, region = get_account_and_region(eks)
    eks_clusters = []
    try:
        clusters_response = eks.list_clusters()
        for cluster_name in clusters_response.get("clusters", []):
            try:
                cluster_info = eks.describe_cluster(name=cluster_name)["cluster"]
                eks_cluster_info = {
                    "Name": cluster_info["name"],
                    "Status": cluster_info["status"],
                    "Version": cluster_info["version"],
                    "Endpoint": cluster_info["endpoint"],
                    "CreatedAt": cluster_info["createdAt"].strftime("%Y-%m-%d %H:%M:%S"),
                    "AccountId": account_id,
                    "Region": region
                }
                eks_clusters.append(eks_cluster_info)
            except ClientError as e:
                logging.error(f"Error describing EKS cluster {cluster_name}: {e}")
    except ClientError as e:
        logging.error(f"Error retrieving EKS clusters: {e}")
    return eks_clusters

def get_spot_instance_requests():
    ec2 = boto3.client('ec2')
    account_id, region = get_account_and_region(ec2)
    spot_requests = []
    try:
        paginator = ec2.get_paginator('describe_spot_instance_requests')
        for page in paginator.paginate():
            for req in page.get("SpotInstanceRequests", []):
                spot_info = {
                    "SpotInstanceRequestId": req["SpotInstanceRequestId"],
                    "State": req["State"],
                    "StatusCode": req["Status"]["Code"],
                    "StatusMessage": req["Status"].get("Message", ""),
                    "InstanceId": req.get("InstanceId", "N/A"),
                    "LaunchSpecification": req.get("LaunchSpecification", {}),
                    "CreateTime": req["CreateTime"].strftime("%Y-%m-%d %H:%M:%S"),
                    "AccountId": account_id,
                    "Region": region
                }
                spot_requests.append(spot_info)
    except ClientError as e:
        logging.error(f"Error retrieving Spot Instance Requests: {e}")
    return spot_requests

def get_iam_users():
    iam = boto3.client('iam')
    account_id, region = get_account_and_region(iam)
    users = []
    try:
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page.get("Users", []):
                user_info = {
                    "UserName": user["UserName"],
                    "UserId": user["UserId"],
                    "CreateDate": user["CreateDate"].strftime("%Y-%m-%d %H:%M:%S"),
                    "Arn": user["Arn"],
                    "AccountId": account_id,
                    "Region": region
                }
                users.append(user_info)
    except ClientError as e:
        logging.error(f"Error retrieving IAM users: {e}")
    return users

def get_iam_roles():
    iam = boto3.client('iam')
    account_id, region = get_account_and_region(iam)
    roles = []
    try:
        paginator = iam.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                role_info = {
                    "RoleName": role["RoleName"],
                    "RoleId": role["RoleId"],
                    "CreateDate": role["CreateDate"].strftime("%Y-%m-%d %H:%M:%S"),
                    "Arn": role["Arn"],
                    "AccountId": account_id,
                    "Region": region
                }
                roles.append(role_info)
    except ClientError as e:
        logging.error(f"Error retrieving IAM roles: {e}")
    return roles

def get_cloudfront_distributions():
    cf = boto3.client('cloudfront')
    account_id, region = get_account_and_region(cf)
    distributions = []
    try:
        paginator = cf.get_paginator('list_distributions')
        for page in paginator.paginate():
            for dist in page.get("DistributionList", {}).get("Items", []):
                dist_info = {
                    "Id": dist["Id"],
                    "DomainName": dist["DomainName"],
                    "Status": dist["Status"],
                    "LastModifiedTime": dist["LastModifiedTime"].strftime("%Y-%m-%d %H:%M:%S"),
                    "AccountId": account_id,
                    "Region": region
                }
                distributions.append(dist_info)
    except ClientError as e:
        logging.error(f"Error retrieving CloudFront distributions: {e}")
    return distributions

def get_dynamodb_tables():
    dynamodb = boto3.client('dynamodb')
    account_id, region = get_account_and_region(dynamodb)
    tables = []
    try:
        paginator = dynamodb.get_paginator('list_tables')
        for page in paginator.paginate():
            for table_name in page.get("TableNames", []):
                try:
                    desc = dynamodb.describe_table(TableName=table_name)["Table"]
                    table_info = {
                        "TableName": desc["TableName"],
                        "TableStatus": desc["TableStatus"],
                        "ItemCount": desc.get("ItemCount", 0),
                        "CreationDateTime": desc["CreationDateTime"].strftime("%Y-%m-%d %H:%M:%S"),
                        "AccountId": account_id,
                        "Region": region
                    }
                    tables.append(table_info)
                except ClientError as e:
                    logging.error(f"Error describing DynamoDB table {table_name}: {e}")
    except ClientError as e:
        logging.error(f"Error retrieving DynamoDB tables: {e}")
    return tables

def get_elbv2_load_balancers():
    elbv2 = boto3.client('elbv2')
    account_id, region = get_account_and_region(elbv2)
    lbs = []
    try:
        paginator = elbv2.get_paginator('describe_load_balancers')
        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                lb_info = {
                    "LoadBalancerName": lb["LoadBalancerName"],
                    "DNSName": lb["DNSName"],
                    "Type": lb["Type"],
                    "State": lb["State"]["Code"],
                    "CreatedTime": lb["CreatedTime"].strftime("%Y-%m-%d %H:%M:%S"),
                    "AccountId": account_id,
                    "Region": region
                }
                lbs.append(lb_info)
    except ClientError as e:
        logging.error(f"Error retrieving ELBv2 load balancers: {e}")
    return lbs

def get_sns_topics():
    sns = boto3.client('sns')
    account_id, region = get_account_and_region(sns)
    topics = []
    try:
        paginator = sns.get_paginator('list_topics')
        for page in paginator.paginate():
            for topic in page.get("Topics", []):
                topics.append({
                    "TopicArn": topic["TopicArn"],
                    "AccountId": account_id,
                    "Region": region
                })
    except ClientError as e:
        logging.error(f"Error retrieving SNS topics: {e}")
    return topics

def get_sqs_queues():
    sqs = boto3.client('sqs')
    account_id, region = get_account_and_region(sqs)
    queues = []
    try:
        response = sqs.list_queues()
        for url in response.get("QueueUrls", []):
            queues.append({
                "QueueUrl": url,
                "AccountId": account_id,
                "Region": region
            })
    except ClientError as e:
        logging.error(f"Error retrieving SQS queues: {e}")
    return queues

def get_cloudformation_stacks():
    cfn = boto3.client('cloudformation')
    account_id, region = get_account_and_region(cfn)
    stacks = []
    try:
        paginator = cfn.get_paginator('describe_stacks')
        for page in paginator.paginate():
            for stack in page.get("Stacks", []):
                stack_info = {
                    "StackName": stack["StackName"],
                    "StackStatus": stack["StackStatus"],
                    "CreationTime": stack["CreationTime"].strftime("%Y-%m-%d %H:%M:%S"),
                    "AccountId": account_id,
                    "Region": region
                }
                stacks.append(stack_info)
    except ClientError as e:
        logging.error(f"Error retrieving CloudFormation stacks: {e}")
    return stacks

def get_ecr_repositories():
    ecr = boto3.client('ecr')
    account_id, region = get_account_and_region(ecr)
    repos = []
    try:
        paginator = ecr.get_paginator('describe_repositories')
        for page in paginator.paginate():
            for repo in page.get("repositories", []):
                repo_info = {
                    "RepositoryName": repo["repositoryName"],
                    "RepositoryUri": repo["repositoryUri"],
                    "CreatedAt": repo["createdAt"].strftime("%Y-%m-%d %H:%M:%S"),
                    "RegistryId": repo["registryId"],
                    "AccountId": account_id,
                    "Region": region
                }
                repos.append(repo_info)
    except ClientError as e:
        logging.error(f"Error retrieving ECR repositories: {e}")
    return repos

def get_docdb_clusters():
    docdb = boto3.client('docdb')
    account_id, region = get_account_and_region(docdb)
    clusters = []
    try:
        paginator = docdb.get_paginator('describe_db_clusters')
        for page in paginator.paginate():
            for cluster in page.get("DBClusters", []):
                cluster_info = {
                    "DBClusterIdentifier": cluster["DBClusterIdentifier"],
                    "Status": cluster["Status"],
                    "Engine": cluster["Engine"],
                    "EngineVersion": cluster["EngineVersion"],
                    "Endpoint": cluster.get("Endpoint", "N/A"),
                    "ClusterCreateTime": cluster["ClusterCreateTime"].strftime("%Y-%m-%d %H:%M:%S"),
                    "AccountId": account_id,
                    "Region": region
                }
                clusters.append(cluster_info)
    except ClientError as e:
        logging.error(f"Error retrieving DocumentDB clusters: {e}")
    return clusters

def get_redshift_clusters():
    redshift = boto3.client('redshift')
    account_id, region = get_account_and_region(redshift)
    clusters = []
    try:
        paginator = redshift.get_paginator('describe_clusters')
        for page in paginator.paginate():
            for cluster in page.get("Clusters", []):
                cluster_info = {
                    "ClusterIdentifier": cluster["ClusterIdentifier"],
                    "NodeType": cluster["NodeType"],
                    "ClusterStatus": cluster["ClusterStatus"],
                    "ClusterCreateTime": cluster["ClusterCreateTime"].strftime("%Y-%m-%d %H:%M:%S"),
                    "Endpoint": cluster.get("Endpoint", {}).get("Address", "N/A"),
                    "AccountId": account_id,
                    "Region": region
                }
                clusters.append(cluster_info)
    except ClientError as e:
        logging.error(f"Error retrieving Redshift clusters: {e}")
    return clusters

def get_elasticache_clusters():
    elasticache = boto3.client('elasticache')
    account_id, region = get_account_and_region(elasticache)
    clusters = []
    try:
        paginator = elasticache.get_paginator('describe_cache_clusters')
        for page in paginator.paginate(ShowCacheNodeInfo=True):
            for cluster in page.get("CacheClusters", []):
                cluster_info = {
                    "CacheClusterId": cluster["CacheClusterId"],
                    "Engine": cluster["Engine"],
                    "EngineVersion": cluster["EngineVersion"],
                    "CacheClusterStatus": cluster["CacheClusterStatus"],
                    "NumCacheNodes": cluster["NumCacheNodes"],
                    "CacheNodeType": cluster["CacheNodeType"],
                    "CacheClusterCreateTime": cluster["CacheClusterCreateTime"].strftime("%Y-%m-%d %H:%M:%S"),
                    "AccountId": account_id,
                    "Region": region
                }
                clusters.append(cluster_info)
    except ClientError as e:
        logging.error(f"Error retrieving ElastiCache clusters: {e}")
    return clusters

def get_efs_file_systems():
    efs = boto3.client('efs')
    account_id, region = get_account_and_region(efs)
    filesystems = []
    try:
        response = efs.describe_file_systems()
        for fs in response.get("FileSystems", []):
            fs_info = {
                "FileSystemId": fs["FileSystemId"],
                "CreationTime": fs["CreationTime"].strftime("%Y-%m-%d %H:%M:%S"),
                "LifeCycleState": fs["LifeCycleState"],
                "NumberOfMountTargets": fs["NumberOfMountTargets"],
                "SizeInBytes": fs["SizeInBytes"]["Value"],
                "AccountId": account_id,
                "Region": region
            }
            filesystems.append(fs_info)
    except ClientError as e:
        logging.error(f"Error retrieving EFS file systems: {e}")
    return filesystems

def get_fsx_file_systems():
    fsx = boto3.client('fsx')
    account_id, region = get_account_and_region(fsx)
    filesystems = []
    try:
        paginator = fsx.get_paginator('describe_file_systems')
        for page in paginator.paginate():
            for fs in page.get("FileSystems", []):
                fs_info = {
                    "FileSystemId": fs["FileSystemId"],
                    "FileSystemType": fs["FileSystemType"],
                    "Lifecycle": fs["Lifecycle"],
                    "CreationTime": fs["CreationTime"].strftime("%Y-%m-%d %H:%M:%S"),
                    "StorageCapacity": fs["StorageCapacity"],
                    "AccountId": account_id,
                    "Region": region
                }
                filesystems.append(fs_info)
    except ClientError as e:
        logging.error(f"Error retrieving FSx file systems: {e}")
    return filesystems

def get_glacier_vaults():
    glacier = boto3.client('glacier')
    account_id, region = get_account_and_region(glacier)
    vaults = []
    try:
        paginator = glacier.get_paginator('list_vaults')
        for page in paginator.paginate():
            for vault in page.get("VaultList", []):
                vault_info = {
                    "VaultName": vault["VaultName"],
                    "CreationDate": vault["CreationDate"],
                    "NumberOfArchives": vault.get("NumberOfArchives", 0),
                    "SizeInBytes": vault.get("SizeInBytes", 0),
                    "AccountId": account_id,
                    "Region": region
                }
                vaults.append(vault_info)
    except ClientError as e:
        logging.error(f"Error retrieving Glacier vaults: {e}")
    return vaults

def get_backup_vaults():
    backup = boto3.client('backup')
    account_id, region = get_account_and_region(backup)
    vaults = []
    try:
        paginator = backup.get_paginator('list_backup_vaults')
        for page in paginator.paginate():
            for vault in page.get("BackupVaultList", []):
                vault_info = {
                    "BackupVaultName": vault["BackupVaultName"],
                    "CreationDate": vault["CreationDate"].strftime("%Y-%m-%d %H:%M:%S"),
                    "NumberOfRecoveryPoints": vault.get("NumberOfRecoveryPoints", 0),
                    "Arn": vault["BackupVaultArn"],
                    "AccountId": account_id,
                    "Region": region
                }
                vaults.append(vault_info)
    except ClientError as e:
        logging.error(f"Error retrieving AWS Backup vaults: {e}")
    return vaults

def save_inventory_to_csv(inventory, filename):
    """
    Salva uma lista de dicionários em um arquivo CSV.
    """
    if not inventory:
        logging.warning(f"Nenhum dado para salvar em {filename}.")
        return
    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=inventory[0].keys())
            writer.writeheader()
            writer.writerows(inventory)
        logging.info(f"Inventário salvo em {filename}")
    except Exception as e:
        logging.error(f"Erro ao salvar inventário em CSV: {e}")

def print_inventory(inventory, title):
    logging.info(f"\n{title}:")
    if not inventory:
        logging.info("No data available.")
    else:
        for item in inventory:
            logging.info(item)

def main():
    logging.info("Getting EC2 instances inventory...")
    ec2_inventory = get_ec2_inventory()
    print_inventory(ec2_inventory, "EC2 Instances Inventory")
    save_inventory_to_csv(ec2_inventory, "ec2_inventory.csv")

    logging.info("Getting RDS instances inventory...")
    rds_inventory = get_rds_inventory()
    print_inventory(rds_inventory, "RDS Instances Inventory")
    save_inventory_to_csv(rds_inventory, "rds_inventory.csv")

    logging.info("Getting S3 buckets inventory...")
    s3_inventory = get_s3_inventory()
    print_inventory(s3_inventory, "S3 Buckets Inventory")
    save_inventory_to_csv(s3_inventory, "s3_inventory.csv")

    logging.info("Getting Lambda functions inventory...")
    lambda_inventory = get_lambda_inventory()
    print_inventory(lambda_inventory, "Lambda Functions Inventory")
    save_inventory_to_csv(lambda_inventory, "lambda_inventory.csv")

    logging.info("Getting EKS clusters inventory...")
    eks_inventory = get_eks_inventory()
    print_inventory(eks_inventory, "EKS Clusters Inventory")
    save_inventory_to_csv(eks_inventory, "eks_inventory.csv")

    logging.info("Getting Spot Instance Requests inventory...")
    spot_inventory = get_spot_instance_requests()
    print_inventory(spot_inventory, "Spot Instance Requests Inventory")
    save_inventory_to_csv(spot_inventory, "spot_inventory.csv")

    logging.info("Getting IAM users inventory...")
    iam_users_inventory = get_iam_users()
    print_inventory(iam_users_inventory, "IAM Users Inventory")
    save_inventory_to_csv(iam_users_inventory, "iam_users_inventory.csv")

    logging.info("Getting IAM roles inventory...")
    iam_roles_inventory = get_iam_roles()
    print_inventory(iam_roles_inventory, "IAM Roles Inventory")
    save_inventory_to_csv(iam_roles_inventory, "iam_roles_inventory.csv")

    logging.info("Getting CloudFront distributions inventory...")
    cloudfront_inventory = get_cloudfront_distributions()
    print_inventory(cloudfront_inventory, "CloudFront Distributions Inventory")
    save_inventory_to_csv(cloudfront_inventory, "cloudfront_inventory.csv")

    logging.info("Getting DynamoDB tables inventory...")
    dynamodb_inventory = get_dynamodb_tables()
    print_inventory(dynamodb_inventory, "DynamoDB Tables Inventory")
    save_inventory_to_csv(dynamodb_inventory, "dynamodb_inventory.csv")

    logging.info("Getting ELBv2 load balancers inventory...")
    elbv2_inventory = get_elbv2_load_balancers()
    print_inventory(elbv2_inventory, "ELBv2 Load Balancers Inventory")
    save_inventory_to_csv(elbv2_inventory, "elbv2_inventory.csv")

    logging.info("Getting SNS topics inventory...")
    sns_inventory = get_sns_topics()
    print_inventory(sns_inventory, "SNS Topics Inventory")
    save_inventory_to_csv(sns_inventory, "sns_inventory.csv")

    logging.info("Getting SQS queues inventory...")
    sqs_inventory = get_sqs_queues()
    print_inventory(sqs_inventory, "SQS Queues Inventory")
    save_inventory_to_csv(sqs_inventory, "sqs_inventory.csv")

    logging.info("Getting CloudFormation stacks inventory...")
    cloudformation_inventory = get_cloudformation_stacks()
    print_inventory(cloudformation_inventory, "CloudFormation Stacks Inventory")
    save_inventory_to_csv(cloudformation_inventory, "cloudformation_inventory.csv")

    logging.info("Getting ECR repositories inventory...")
    ecr_inventory = get_ecr_repositories()
    print_inventory(ecr_inventory, "ECR Repositories Inventory")
    save_inventory_to_csv(ecr_inventory, "ecr_inventory.csv")

    logging.info("Getting DocumentDB clusters inventory...")
    docdb_inventory = get_docdb_clusters()
    print_inventory(docdb_inventory, "DocumentDB Clusters Inventory")
    save_inventory_to_csv(docdb_inventory, "docdb_inventory.csv")

    logging.info("Getting Redshift clusters inventory...")
    redshift_inventory = get_redshift_clusters()
    print_inventory(redshift_inventory, "Redshift Clusters Inventory")
    save_inventory_to_csv(redshift_inventory, "redshift_inventory.csv")

    logging.info("Getting ElastiCache clusters inventory...")
    elasticache_inventory = get_elasticache_clusters()
    print_inventory(elasticache_inventory, "ElastiCache Clusters Inventory")
    save_inventory_to_csv(elasticache_inventory, "elasticache_inventory.csv")

    logging.info("Getting EFS file systems inventory...")
    efs_inventory = get_efs_file_systems()
    print_inventory(efs_inventory, "EFS File Systems Inventory")
    save_inventory_to_csv(efs_inventory, "efs_inventory.csv")

    logging.info("Getting FSx file systems inventory...")
    fsx_inventory = get_fsx_file_systems()
    print_inventory(fsx_inventory, "FSx File Systems Inventory")
    save_inventory_to_csv(fsx_inventory, "fsx_inventory.csv")

    logging.info("Getting Glacier vaults inventory...")
    glacier_inventory = get_glacier_vaults()
    print_inventory(glacier_inventory, "Glacier Vaults Inventory")
    save_inventory_to_csv(glacier_inventory, "glacier_inventory.csv")

    logging.info("Getting AWS Backup vaults inventory...")
    backup_inventory = get_backup_vaults()
    print_inventory(backup_inventory, "AWS Backup Vaults Inventory")
    save_inventory_to_csv(backup_inventory, "backup_inventory.csv")

if __name__ == "__main__":
    main()
