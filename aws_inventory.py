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
                    # Coleta o sistema operacional da imagem (AMI)
                    os_name = "N/A"
                    image_id = instance.get("ImageId")
                    if image_id:
                        try:
                            images = ec2.describe_images(ImageIds=[image_id]).get("Images", [])
                            if images:
                                os_name = images[0].get("PlatformDetails", images[0].get("Description", "N/A"))
                        except Exception as e:
                            logging.warning(f"Could not get OS for instance {instance['InstanceId']}: {e}")
                    instance_info = {
                        "InstanceId": instance["InstanceId"],
                        "InstanceType": instance["InstanceType"],
                        "LaunchTime": instance["LaunchTime"].strftime("%Y-%m-%d %H:%M:%S"),
                        "State": instance["State"]["Name"],
                        "PrivateIpAddress": instance.get("PrivateIpAddress", "N/A"),
                        "PublicIpAddress": instance.get("PublicIpAddress", "N/A"),
                        "Name": next((tag["Value"] for tag in instance.get("Tags", []) if tag["Key"] == "Name"), "N/A"),
                        "OS": os_name,  # Adicionado campo do sistema operacional
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
                    "AllocatedStorageGiB": instance.get("AllocatedStorage", "N/A"),  # Adicionado campo de tamanho alocado
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
            bucket_name = bucket["Name"]
            # Coleta o tamanho total dos objetos do bucket
            total_size = 0
            try:
                paginator = s3.get_paginator('list_objects_v2')
                for page in paginator.paginate(Bucket=bucket_name):
                    for obj in page.get("Contents", []):
                        total_size += obj.get("Size", 0)
            except Exception as e:
                logging.warning(f"Could not get size for bucket {bucket_name}: {e}")
            s3_bucket_info = {
                "Name": bucket_name,
                "CreationDate": bucket["CreationDate"].strftime("%Y-%m-%d %H:%M:%S"),
                "TotalSizeBytes": total_size,
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
                    "Runtime": function.get("Runtime", "N/A"),  # Corrigido para evitar KeyError
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
    import ast
    ec2 = boto3.client('ec2')
    account_id, region = get_account_and_region(ec2)
    spot_requests = []
    try:
        paginator = ec2.get_paginator('describe_spot_instance_requests')
        for page in paginator.paginate():
            for req in page.get("SpotInstanceRequests", []):
                # Coleta o tamanho alocado do EBS, se disponível
                allocated_storage_gib = "N/A"
                launch_spec = req.get("LaunchSpecification", {})
                block_devices = launch_spec.get("BlockDeviceMappings", [])
                if block_devices and isinstance(block_devices, list):
                    ebs = block_devices[0].get("Ebs", {}) if block_devices else {}
                    allocated_storage_gib = ebs.get("VolumeSize", "N/A")
                # Coleta o sistema operacional da imagem (AMI)
                os_name = "N/A"
                image_id = launch_spec.get("ImageId")
                if image_id:
                    try:
                        images = ec2.describe_images(ImageIds=[image_id]).get("Images", [])
                        if images:
                            os_name = images[0].get("PlatformDetails", images[0].get("Description", "N/A"))
                    except Exception as e:
                        logging.warning(f"Could not get OS for Spot request {req['SpotInstanceRequestId']}: {e}")
                spot_info = {
                    "SpotInstanceRequestId": req["SpotInstanceRequestId"],
                    "State": req["State"],
                    "StatusCode": req["Status"]["Code"],
                    "StatusMessage": req["Status"].get("Message", ""),
                    "InstanceId": req.get("InstanceId", "N/A"),
                    "LaunchSpecification": launch_spec,
                    "AllocatedStorageGiB": allocated_storage_gib,
                    "OS": os_name,  # Adicionado campo do sistema operacional
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
                # Coletar o tamanho total dos backups no vault
                total_size_bytes = 0
                try:
                    # Listar recovery points para o vault e somar o tamanho
                    rp_paginator = backup.get_paginator('list_recovery_points_by_backup_vault')
                    for rp_page in rp_paginator.paginate(BackupVaultName=vault["BackupVaultName"]):
                        for rp in rp_page.get("RecoveryPoints", []):
                            total_size_bytes += rp.get("BackupSizeInBytes", 0)
                except Exception as e:
                    logging.warning(f"Could not get size for backup vault {vault['BackupVaultName']}: {e}")
                vault_info = {
                    "BackupVaultName": vault["BackupVaultName"],
                    "CreationDate": vault["CreationDate"].strftime("%Y-%m-%d %H:%M:%S"),
                    "NumberOfRecoveryPoints": vault.get("NumberOfRecoveryPoints", 0),
                    "TotalBackupSizeBytes": total_size_bytes,  # Adicionado campo de tamanho total
                    "Arn": vault["BackupVaultArn"],
                    "AccountId": account_id,
                    "Region": region
                }
                vaults.append(vault_info)
    except ClientError as e:
        logging.error(f"Error retrieving AWS Backup vaults: {e}")
    return vaults

def get_ebs_volumes():
    """
    Coleta informações dos volumes EBS, incluindo o tamanho em GiB.
    """
    ec2 = boto3.client('ec2')
    account_id, region = get_account_and_region(ec2)
    volumes = []
    try:
        paginator = ec2.get_paginator('describe_volumes')
        for page in paginator.paginate():
            for vol in page.get("Volumes", []):
                vol_info = {
                    "VolumeId": vol["VolumeId"],
                    "SizeGiB": vol["Size"],  # Renomeado para clareza
                    "State": vol["State"],
                    "VolumeType": vol["VolumeType"],
                    "CreateTime": vol["CreateTime"].strftime("%Y-%m-%d %H:%M:%S"),
                    "AvailabilityZone": vol["AvailabilityZone"],
                    "Encrypted": vol["Encrypted"],
                    "Attachments": [
                        {
                            "InstanceId": att.get("InstanceId", "N/A"),
                            "State": att.get("State", "N/A")
                        } for att in vol.get("Attachments", [])
                    ],
                    "AccountId": account_id,
                    "Region": region
                }
                volumes.append(vol_info)
    except ClientError as e:
        logging.error(f"Error retrieving EBS volumes: {e}")
    return volumes

def save_inventory_to_csv(inventory, filename, account_id=None):
    """
    Salva uma lista de dicionários em um arquivo CSV.
    O nome do arquivo inclui o account_id se fornecido.
    """
    if not inventory:
        logging.warning(f"Nenhum dado para salvar em {filename}.")
        return
    if account_id:
        filename = f"{account_id}_{filename}"
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
    # Obter account_id uma vez para uso nos nomes dos arquivos
    sts = boto3.client('sts')
    account_id = sts.get_caller_identity()["Account"]

    logging.info("Getting EC2 instances inventory...")
    ec2_inventory = get_ec2_inventory()
    print_inventory(ec2_inventory, "EC2 Instances Inventory")
    save_inventory_to_csv(ec2_inventory, "ec2_inventory.csv", account_id)

    logging.info("Getting RDS instances inventory...")
    rds_inventory = get_rds_inventory()
    print_inventory(rds_inventory, "RDS Instances Inventory")
    save_inventory_to_csv(rds_inventory, "rds_inventory.csv", account_id)

    logging.info("Getting S3 buckets inventory...")
    s3_inventory = get_s3_inventory()
    print_inventory(s3_inventory, "S3 Buckets Inventory")
    save_inventory_to_csv(s3_inventory, "s3_inventory.csv", account_id)

    logging.info("Getting Lambda functions inventory...")
    lambda_inventory = get_lambda_inventory()
    print_inventory(lambda_inventory, "Lambda Functions Inventory")
    save_inventory_to_csv(lambda_inventory, "lambda_inventory.csv", account_id)

    logging.info("Getting EKS clusters inventory...")
    eks_inventory = get_eks_inventory()
    print_inventory(eks_inventory, "EKS Clusters Inventory")
    save_inventory_to_csv(eks_inventory, "eks_inventory.csv", account_id)

    logging.info("Getting Spot Instance Requests inventory...")
    spot_inventory = get_spot_instance_requests()
    print_inventory(spot_inventory, "Spot Instance Requests Inventory")
    save_inventory_to_csv(spot_inventory, "spot_inventory.csv", account_id)

    logging.info("Getting IAM users inventory...")
    iam_users_inventory = get_iam_users()
    print_inventory(iam_users_inventory, "IAM Users Inventory")
    save_inventory_to_csv(iam_users_inventory, "iam_users_inventory.csv", account_id)

    logging.info("Getting IAM roles inventory...")
    iam_roles_inventory = get_iam_roles()
    print_inventory(iam_roles_inventory, "IAM Roles Inventory")
    save_inventory_to_csv(iam_roles_inventory, "iam_roles_inventory.csv", account_id)

    logging.info("Getting CloudFront distributions inventory...")
    cloudfront_inventory = get_cloudfront_distributions()
    print_inventory(cloudfront_inventory, "CloudFront Distributions Inventory")
    save_inventory_to_csv(cloudfront_inventory, "cloudfront_inventory.csv", account_id)

    logging.info("Getting DynamoDB tables inventory...")
    dynamodb_inventory = get_dynamodb_tables()
    print_inventory(dynamodb_inventory, "DynamoDB Tables Inventory")
    save_inventory_to_csv(dynamodb_inventory, "dynamodb_inventory.csv", account_id)

    logging.info("Getting ELBv2 load balancers inventory...")
    elbv2_inventory = get_elbv2_load_balancers()
    print_inventory(elbv2_inventory, "ELBv2 Load Balancers Inventory")
    save_inventory_to_csv(elbv2_inventory, "elbv2_inventory.csv", account_id)

    logging.info("Getting SNS topics inventory...")
    sns_inventory = get_sns_topics()
    print_inventory(sns_inventory, "SNS Topics Inventory")
    save_inventory_to_csv(sns_inventory, "sns_inventory.csv", account_id)

    logging.info("Getting SQS queues inventory...")
    sqs_inventory = get_sqs_queues()
    print_inventory(sqs_inventory, "SQS Queues Inventory")
    save_inventory_to_csv(sqs_inventory, "sqs_inventory.csv", account_id)

    logging.info("Getting CloudFormation stacks inventory...")
    cloudformation_inventory = get_cloudformation_stacks()
    print_inventory(cloudformation_inventory, "CloudFormation Stacks Inventory")
    save_inventory_to_csv(cloudformation_inventory, "cloudformation_inventory.csv", account_id)

    logging.info("Getting ECR repositories inventory...")
    ecr_inventory = get_ecr_repositories()
    print_inventory(ecr_inventory, "ECR Repositories Inventory")
    save_inventory_to_csv(ecr_inventory, "ecr_inventory.csv", account_id)

    logging.info("Getting DocumentDB clusters inventory...")
    docdb_inventory = get_docdb_clusters()
    print_inventory(docdb_inventory, "DocumentDB Clusters Inventory")
    save_inventory_to_csv(docdb_inventory, "docdb_inventory.csv", account_id)

    logging.info("Getting Redshift clusters inventory...")
    redshift_inventory = get_redshift_clusters()
    print_inventory(redshift_inventory, "Redshift Clusters Inventory")
    save_inventory_to_csv(redshift_inventory, "redshift_inventory.csv", account_id)

    logging.info("Getting ElastiCache clusters inventory...")
    elasticache_inventory = get_elasticache_clusters()
    print_inventory(elasticache_inventory, "ElastiCache Clusters Inventory")
    save_inventory_to_csv(elasticache_inventory, "elasticache_inventory.csv", account_id)

    logging.info("Getting EFS file systems inventory...")
    efs_inventory = get_efs_file_systems()
    print_inventory(efs_inventory, "EFS File Systems Inventory")
    save_inventory_to_csv(efs_inventory, "efs_inventory.csv", account_id)

    logging.info("Getting FSx file systems inventory...")
    fsx_inventory = get_fsx_file_systems()
    print_inventory(fsx_inventory, "FSx File Systems Inventory")
    save_inventory_to_csv(fsx_inventory, "fsx_inventory.csv", account_id)

    logging.info("Getting Glacier vaults inventory...")
    glacier_inventory = get_glacier_vaults()
    print_inventory(glacier_inventory, "Glacier Vaults Inventory")
    save_inventory_to_csv(glacier_inventory, "glacier_inventory.csv", account_id)

    logging.info("Getting AWS Backup vaults inventory...")
    backup_inventory = get_backup_vaults()
    print_inventory(backup_inventory, "AWS Backup Vaults Inventory")
    save_inventory_to_csv(backup_inventory, "backup_inventory.csv", account_id)

    logging.info("Getting EBS volumes inventory...")
    ebs_inventory = get_ebs_volumes()
    print_inventory(ebs_inventory, "EBS Volumes Inventory")
    save_inventory_to_csv(ebs_inventory, "ebs_inventory.csv", account_id)

    logging.info("Getting VPCs inventory...")
    vpc_inventory = get_vpc_inventory()
    print_inventory(vpc_inventory, "VPCs Inventory")
    save_inventory_to_csv(vpc_inventory, "vpc_inventory.csv", account_id)

    logging.info("Getting EC2 Security Groups inventory...")
    ec2_sg_inventory = get_ec2_security_groups_inventory()
    print_inventory(ec2_sg_inventory, "EC2 Security Groups Inventory")
    save_inventory_to_csv(ec2_sg_inventory, "ec2_sg_inventory.csv", account_id)

    logging.info("Getting EC2 Key Pairs inventory...")
    ec2_keypair_inventory = get_ec2_key_pairs_inventory()
    print_inventory(ec2_keypair_inventory, "EC2 Key Pairs Inventory")
    save_inventory_to_csv(ec2_keypair_inventory, "ec2_keypair_inventory.csv", account_id)

    logging.info("Getting ACM certificates inventory...")
    acm_inventory = get_acm_inventory()
    print_inventory(acm_inventory, "ACM Certificates Inventory")
    save_inventory_to_csv(acm_inventory, "acm_inventory.csv", account_id)

    logging.info("Getting Route53 Hosted Zones inventory...")
    route53_zones_inventory = get_route53_hosted_zones_inventory()
    print_inventory(route53_zones_inventory, "Route53 Hosted Zones Inventory")
    save_inventory_to_csv(route53_zones_inventory, "route53_zones_inventory.csv", account_id)

    logging.info("Getting Route53 Records inventory...")
    route53_records_inventory = get_route53_records_inventory()
    print_inventory(route53_records_inventory, "Route53 Records Inventory")
    save_inventory_to_csv(route53_records_inventory, "route53_records_inventory.csv", account_id)

    logging.info("Getting Elastic Beanstalk environments inventory...")
    elastic_beanstalk_inventory = get_elastic_beanstalk_inventory()
    print_inventory(elastic_beanstalk_inventory, "Elastic Beanstalk Environments Inventory")
    save_inventory_to_csv(elastic_beanstalk_inventory, "elastic_beanstalk_inventory.csv", account_id)

    logging.info("Getting Elastic IPs inventory...")
    elastic_ips_inventory = get_elastic_ips_inventory()
    print_inventory(elastic_ips_inventory, "Elastic IPs Inventory")
    save_inventory_to_csv(elastic_ips_inventory, "elastic_ips_inventory.csv", account_id)

    logging.info("Getting KMS keys inventory...")
    kms_inventory = get_kms_inventory()
    print_inventory(kms_inventory, "KMS Keys Inventory")
    save_inventory_to_csv(kms_inventory, "kms_inventory.csv", account_id)

    logging.info("Getting Secrets Manager secrets inventory...")
    secrets_manager_inventory = get_secrets_manager_inventory()
    print_inventory(secrets_manager_inventory, "Secrets Manager Secrets Inventory")
    save_inventory_to_csv(secrets_manager_inventory, "secrets_manager_inventory.csv", account_id)

    logging.info("Getting SSM parameters inventory...")
    ssm_inventory = get_ssm_inventory()
    print_inventory(ssm_inventory, "SSM Parameters Inventory")
    save_inventory_to_csv(ssm_inventory, "ssm_inventory.csv", account_id)

    logging.info("Getting Step Functions inventory...")
    stepfunctions_inventory = get_stepfunctions_inventory()
    print_inventory(stepfunctions_inventory, "Step Functions Inventory")
    save_inventory_to_csv(stepfunctions_inventory, "stepfunctions_inventory.csv", account_id)

    logging.info("Getting API Gateway APIs inventory...")
    apigateway_inventory = get_apigateway_inventory()
    print_inventory(apigateway_inventory, "API Gateway APIs Inventory")
    save_inventory_to_csv(apigateway_inventory, "apigateway_inventory.csv", account_id)

    logging.info("Getting AppSync APIs inventory...")
    appsync_inventory = get_appsync_inventory()
    print_inventory(appsync_inventory, "AppSync APIs Inventory")
    save_inventory_to_csv(appsync_inventory, "appsync_inventory.csv", account_id)

    logging.info("Getting CodeBuild projects inventory...")
    codebuild_inventory = get_codebuild_inventory()
    print_inventory(codebuild_inventory, "CodeBuild Projects Inventory")
    save_inventory_to_csv(codebuild_inventory, "codebuild_inventory.csv", account_id)

    logging.info("Getting CodePipeline pipelines inventory...")
    codepipeline_inventory = get_codepipeline_inventory()
    print_inventory(codepipeline_inventory, "CodePipeline Pipelines Inventory")
    save_inventory_to_csv(codepipeline_inventory, "codepipeline_inventory.csv", account_id)

    logging.info("Getting CodeDeploy applications inventory...")
    codedeploy_inventory = get_codedeploy_inventory()
    print_inventory(codedeploy_inventory, "CodeDeploy Applications Inventory")
    save_inventory_to_csv(codedeploy_inventory, "codedeploy_inventory.csv", account_id)

    logging.info("Getting CloudWatch alarms inventory...")
    cloudwatch_alarms_inventory = get_cloudwatch_alarms_inventory()
    print_inventory(cloudwatch_alarms_inventory, "CloudWatch Alarms Inventory")
    save_inventory_to_csv(cloudwatch_alarms_inventory, "cloudwatch_alarms_inventory.csv", account_id)

    logging.info("Getting CloudWatch log groups inventory...")
    cloudwatch_log_groups_inventory = get_cloudwatch_log_groups_inventory()
    print_inventory(cloudwatch_log_groups_inventory, "CloudWatch Log Groups Inventory")
    save_inventory_to_csv(cloudwatch_log_groups_inventory, "cloudwatch_log_groups_inventory.csv", account_id)

    logging.info("Getting Organizations inventory...")
    organizations_inventory = get_organizations_inventory()
    print_inventory(organizations_inventory, "Organizations Inventory")
    save_inventory_to_csv(organizations_inventory, "organizations_inventory.csv", account_id)

    logging.info("Getting Cost Explorer inventory...")
    cost_explorer_inventory = get_cost_explorer_inventory()
    print_inventory(cost_explorer_inventory, "Cost Explorer Inventory")
    save_inventory_to_csv(cost_explorer_inventory, "cost_explorer_inventory.csv", account_id)

    logging.info("Getting WAF inventory...")
    waf_inventory = get_waf_inventory()
    print_inventory(waf_inventory, "WAF Inventory")
    save_inventory_to_csv(waf_inventory, "waf_inventory.csv", account_id)

    logging.info("Getting Shield inventory...")
    shield_inventory = get_shield_inventory()
    print_inventory(shield_inventory, "Shield Inventory")
    save_inventory_to_csv(shield_inventory, "shield_inventory.csv", account_id)

    logging.info("Getting SageMaker inventory...")
    sagemaker_inventory = get_sagemaker_inventory()
    print_inventory(sagemaker_inventory, "SageMaker Inventory")
    save_inventory_to_csv(sagemaker_inventory, "sagemaker_inventory.csv", account_id)

    logging.info("Getting Athena inventory...")
    athena_inventory = get_athena_inventory()
    print_inventory(athena_inventory, "Athena Inventory")
    save_inventory_to_csv(athena_inventory, "athena_inventory.csv", account_id)

    logging.info("Getting Glue inventory...")
    glue_inventory = get_glue_inventory()
    print_inventory(glue_inventory, "Glue Inventory")
    save_inventory_to_csv(glue_inventory, "glue_inventory.csv", account_id)

    logging.info("Getting MSK inventory...")
    msk_inventory = get_msk_inventory()
    print_inventory(msk_inventory, "MSK Inventory")
    save_inventory_to_csv(msk_inventory, "msk_inventory.csv", account_id)

    logging.info("Getting Direct Connect inventory...")
    directconnect_inventory = get_directconnect_inventory()
    print_inventory(directconnect_inventory, "Direct Connect Inventory")
    save_inventory_to_csv(directconnect_inventory, "directconnect_inventory.csv", account_id)

    logging.info("Getting Outposts inventory...")
    outposts_inventory = get_outposts_inventory()
    print_inventory(outposts_inventory, "Outposts Inventory")
    save_inventory_to_csv(outposts_inventory, "outposts_inventory.csv", account_id)

def get_vpc_inventory():
    ec2 = boto3.client('ec2')
    account_id, region = get_account_and_region(ec2)
    vpcs = []
    try:
        for vpc in ec2.describe_vpcs().get("Vpcs", []):
            vpcs.append({
                "VpcId": vpc["VpcId"],
                "CidrBlock": vpc.get("CidrBlock", ""),
                "State": vpc.get("State", ""),
                "IsDefault": vpc.get("IsDefault", False),
                "AccountId": account_id,
                "Region": region
            })
    except ClientError as e:
        logging.error(f"Error retrieving VPCs: {e}")
    return vpcs

def get_ec2_security_groups_inventory():
    ec2 = boto3.client('ec2')
    account_id, region = get_account_and_region(ec2)
    sgs = []
    try:
        for sg in ec2.describe_security_groups().get("SecurityGroups", []):
            sgs.append({
                "GroupId": sg["GroupId"],
                "GroupName": sg["GroupName"],
                "Description": sg.get("Description", ""),
                "VpcId": sg.get("VpcId", ""),
                "AccountId": account_id,
                "Region": region
            })
    except ClientError as e:
        logging.error(f"Error retrieving Security Groups: {e}")
    return sgs

def get_ec2_key_pairs_inventory():
    ec2 = boto3.client('ec2')
    account_id, region = get_account_and_region(ec2)
    keys = []
    try:
        for kp in ec2.describe_key_pairs().get("KeyPairs", []):
            keys.append({
                "KeyName": kp["KeyName"],
                "KeyPairId": kp.get("KeyPairId", ""),
                "KeyType": kp.get("KeyType", ""),
                "AccountId": account_id,
                "Region": region
            })
    except ClientError as e:
        logging.error(f"Error retrieving Key Pairs: {e}")
    return keys

def get_acm_inventory():
    acm = boto3.client('acm')
    account_id, region = get_account_and_region(acm)
    certs = []
    try:
        paginator = acm.get_paginator('list_certificates')
        for page in paginator.paginate():
            for cert in page.get("CertificateSummaryList", []):
                certs.append({
                    "CertificateArn": cert["CertificateArn"],
                    "DomainName": cert.get("DomainName", ""),
                    "AccountId": account_id,
                    "Region": region
                })
    except ClientError as e:
        logging.error(f"Error retrieving ACM certificates: {e}")
    return certs

def get_route53_hosted_zones_inventory():
    r53 = boto3.client('route53')
    account_id, region = get_account_and_region(r53)
    zones = []
    try:
        for zone in r53.list_hosted_zones().get("HostedZones", []):
            zones.append({
                "Id": zone["Id"],
                "Name": zone["Name"],
                "PrivateZone": zone.get("Config", {}).get("PrivateZone", False),
                "ResourceRecordSetCount": zone.get("ResourceRecordSetCount", 0),
                "AccountId": account_id,
                "Region": region
            })
    except ClientError as e:
        logging.error(f"Error retrieving Route53 Hosted Zones: {e}")
    return zones

def get_route53_records_inventory():
    r53 = boto3.client('route53')
    account_id, region = get_account_and_region(r53)
    records = []
    try:
        for zone in r53.list_hosted_zones().get("HostedZones", []):
            zone_id = zone["Id"]
            paginator = r53.get_paginator('list_resource_record_sets')
            for page in paginator.paginate(HostedZoneId=zone_id):
                for record in page.get("ResourceRecordSets", []):
                    records.append({
                        "HostedZoneId": zone_id,
                        "Name": record.get("Name", ""),
                        "Type": record.get("Type", ""),
                        "TTL": record.get("TTL", ""),
                        "AccountId": account_id,
                        "Region": region
                    })
    except ClientError as e:
        logging.error(f"Error retrieving Route53 Records: {e}")
    return records

def get_elastic_beanstalk_inventory():
    eb = boto3.client('elasticbeanstalk')
    account_id, region = get_account_and_region(eb)
    envs = []
    try:
        for env in eb.describe_environments().get("Environments", []):
            envs.append({
                "EnvironmentName": env["EnvironmentName"],
                "ApplicationName": env["ApplicationName"],
                "Status": env.get("Status", ""),
                "Health": env.get("Health", ""),
                "AccountId": account_id,
                "Region": region
            })
    except ClientError as e:
        logging.error(f"Error retrieving Elastic Beanstalk environments: {e}")
    return envs

def get_elastic_ips_inventory():
    ec2 = boto3.client('ec2')
    account_id, region = get_account_and_region(ec2)
    eips = []
    try:
        for eip in ec2.describe_addresses().get("Addresses", []):
            eips.append({
                "PublicIp": eip.get("PublicIp", ""),
                "AllocationId": eip.get("AllocationId", ""),
                "InstanceId": eip.get("InstanceId", ""),
                "Domain": eip.get("Domain", ""),
                "AccountId": account_id,
                "Region": region
            })
    except ClientError as e:
        logging.error(f"Error retrieving Elastic IPs: {e}")
    return eips

def get_kms_inventory():
    kms = boto3.client('kms')
    account_id, region = get_account_and_region(kms)
    keys = []
    try:
        paginator = kms.get_paginator('list_keys')
        for page in paginator.paginate():
            for key in page.get("Keys", []):
                key_id = key["KeyId"]
                try:
                    desc = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                    keys.append({
                        "KeyId": key_id,
                        "Arn": desc["Arn"],
                        "Description": desc.get("Description", ""),
                        "Enabled": desc.get("Enabled", False),
                        "AccountId": account_id,
                        "Region": region
                    })
                except ClientError as e:
                    logging.error(f"Error describing KMS key {key_id}: {e}")
    except ClientError as e:
        logging.error(f"Error retrieving KMS keys: {e}")
    return keys

def get_secrets_manager_inventory():
    sm = boto3.client('secretsmanager')
    account_id, region = get_account_and_region(sm)
    secrets = []
    try:
        paginator = sm.get_paginator('list_secrets')
        for page in paginator.paginate():
            for secret in page.get("SecretList", []):
                secrets.append({
                    "Name": secret.get("Name", ""),
                    "ARN": secret.get("ARN", ""),
                    "Description": secret.get("Description", ""),
                    "AccountId": account_id,
                    "Region": region
                })
    except ClientError as e:
        logging.error(f"Error retrieving Secrets Manager secrets: {e}")
    return secrets

def get_ssm_inventory():
    ssm = boto3.client('ssm')
    account_id, region = get_account_and_region(ssm)
    params = []
    try:
        paginator = ssm.get_paginator('describe_parameters')
        for page in paginator.paginate():
            for param in page.get("Parameters", []):
                params.append({
                    "Name": param.get("Name", ""),
                    "Type": param.get("Type", ""),
                    "AccountId": account_id,
                    "Region": region
                })
    except ClientError as e:
        logging.error(f"Error retrieving SSM parameters: {e}")
    return params

def get_stepfunctions_inventory():
    sf = boto3.client('stepfunctions')
    account_id, region = get_account_and_region(sf)
    sfs = []
    try:
        paginator = sf.get_paginator('list_state_machines')
        for page in paginator.paginate():
            for sm in page.get("stateMachines", []):
                sfs.append({
                    "StateMachineArn": sm["stateMachineArn"],
                    "Name": sm["name"],
                    "AccountId": account_id,
                    "Region": region
                })
    except ClientError as e:
        logging.error(f"Error retrieving Step Functions: {e}")
    return sfs

def get_apigateway_inventory():
    apigw = boto3.client('apigateway')
    account_id, region = get_account_and_region(apigw)
    apis = []
    try:
        for api in apigw.get_rest_apis().get("items", []):
            apis.append({
                "Id": api["id"],
                "Name": api["name"],
                "Description": api.get("description", ""),
                "AccountId": account_id,
                "Region": region
            })
    except ClientError as e:
        logging.error(f"Error retrieving API Gateway APIs: {e}")
    return apis

def get_appsync_inventory():
    appsync = boto3.client('appsync')
    account_id, region = get_account_and_region(appsync)
    apis = []
    try:
        paginator = appsync.get_paginator('list_graphql_apis')
        for page in paginator.paginate():
            for api in page.get("graphqlApis", []):
                apis.append({
                    "ApiId": api["apiId"],
                    "Name": api["name"],
                    "AuthenticationType": api.get("authenticationType", ""),
                    "AccountId": account_id,
                    "Region": region
                })
    except ClientError as e:
        logging.error(f"Error retrieving AppSync APIs: {e}")
    return apis

def get_codebuild_inventory():
    cb = boto3.client('codebuild')
    account_id, region = get_account_and_region(cb)
    projects = []
    try:
        for name in cb.list_projects().get("projects", []):
            try:
                proj = cb.batch_get_projects(names=[name])["projects"][0]
                projects.append({
                    "Name": proj["name"],
                    "Arn": proj["arn"],
                    "Description": proj.get("description", ""),
                    "AccountId": account_id,
                    "Region": region
                })
            except Exception:
                continue
    except ClientError as e:
        logging.error(f"Error retrieving CodeBuild projects: {e}")
    return projects

def get_codepipeline_inventory():
    cp = boto3.client('codepipeline')
    account_id, region = get_account_and_region(cp)
    pipelines = []
    try:
        for pipe in cp.list_pipelines().get("pipelines", []):
            pipelines.append({
                "Name": pipe["name"],
                "Version": pipe.get("version", ""),
                "AccountId": account_id,
                "Region": region
            })
    except ClientError as e:
        logging.error(f"Error retrieving CodePipeline pipelines: {e}")
    return pipelines

def get_codedeploy_inventory():
    cd = boto3.client('codedeploy')
    account_id, region = get_account_and_region(cd)
    apps = []
    try:
        for app in cd.list_applications().get("applications", []):
            apps.append({
                "ApplicationName": app,
                "AccountId": account_id,
                "Region": region
            })
    except ClientError as e:
        logging.error(f"Error retrieving CodeDeploy applications: {e}")
    return apps

def get_cloudwatch_alarms_inventory():
    cw = boto3.client('cloudwatch')
    account_id, region = get_account_and_region(cw)
    alarms = []
    try:
        paginator = cw.get_paginator('describe_alarms')
        for page in paginator.paginate():
            for alarm in page.get("MetricAlarms", []):
                alarms.append({
                    "AlarmName": alarm["AlarmName"],
                    "StateValue": alarm.get("StateValue", ""),
                    "MetricName": alarm.get("MetricName", ""),
                    "Namespace": alarm.get("Namespace", ""),
                    "AccountId": account_id,
                    "Region": region
                })
    except ClientError as e:
        logging.error(f"Error retrieving CloudWatch alarms: {e}")
    return alarms

def get_cloudwatch_log_groups_inventory():
    logs = boto3.client('logs')
    account_id, region = get_account_and_region(logs)
    groups = []
    try:
        paginator = logs.get_paginator('describe_log_groups')
        for page in paginator.paginate():
            for group in page.get("logGroups", []):
                groups.append({
                    "LogGroupName": group["logGroupName"],
                    "Arn": group.get("arn", ""),
                    "AccountId": account_id,
                    "Region": region
                })
    except ClientError as e:
        logging.error(f"Error retrieving CloudWatch log groups: {e}")
    return groups

def get_organizations_inventory():
    org = boto3.client('organizations')
    account_id, region = get_account_and_region(org)
    orgs = []
    try:
        orgs.append(org.describe_organization()["Organization"])
    except ClientError as e:
        logging.error(f"Error retrieving Organizations: {e}")
    return orgs

def get_cost_explorer_inventory():
    ce = boto3.client('ce')
    account_id, region = get_account_and_region(ce)
    # Only returns account/region, as cost data is complex
    try:
        return [{"AccountId": account_id, "Region": region}]
    except ClientError as e:
        logging.error(f"Error retrieving Cost Explorer data: {e}")
    return []

def get_waf_inventory():
    waf = boto3.client('waf')
    account_id, region = get_account_and_region(waf)
    webacls = []
    try:
        for acl in waf.list_web_acls().get("WebACLs", []):
            webacls.append({
                "WebACLId": acl["WebACLId"],
                "Name": acl["Name"],
                "MetricName": acl.get("MetricName", ""),
                "AccountId": account_id,
                "Region": region
            })
    except ClientError as e:
        logging.error(f"Error retrieving WAF WebACLs: {e}")
    return webacls

def get_shield_inventory():
    shield = boto3.client('shield')
    account_id, region = get_account_and_region(shield)
    protections = []
    try:
        for prot in shield.list_protections().get("Protections", []):
            protections.append({
                "Id": prot["Id"],
                "Name": prot["Name"],
                "ResourceArn": prot.get("ResourceArn", ""),
                "AccountId": account_id,
                "Region": region
            })
    except ClientError as e:
        logging.error(f"Error retrieving Shield protections: {e}")
    return protections

def get_sagemaker_inventory():
    sm = boto3.client('sagemaker')
    account_id, region = get_account_and_region(sm)
    notebooks = []
    try:
        paginator = sm.get_paginator('list_notebook_instances')
        for page in paginator.paginate():
            for nb in page.get("NotebookInstances", []):
                notebooks.append({
                    "NotebookInstanceName": nb["NotebookInstanceName"],
                    "InstanceType": nb.get("InstanceType", ""),
                    "Status": nb.get("NotebookInstanceStatus", ""),
                    "AccountId": account_id,
                    "Region": region
                })
    except ClientError as e:
        logging.error(f"Error retrieving SageMaker notebooks: {e}")
    return notebooks

def get_athena_inventory():
    athena = boto3.client('athena')
    account_id, region = get_account_and_region(athena)
    workgroups = []
    try:
        for wg in athena.list_work_groups().get("WorkGroups", []):
            workgroups.append({
                "Name": wg["Name"],
                "State": wg.get("State", ""),
                "AccountId": account_id,
                "Region": region
            })
    except ClientError as e:
        logging.error(f"Error retrieving Athena workgroups: {e}")
    return workgroups

def get_glue_inventory():
    glue = boto3.client('glue')
    account_id, region = get_account_and_region(glue)
    jobs = []
    try:
        for name in glue.list_jobs().get("JobNames", []):
            jobs.append({
                "JobName": name,
                "AccountId": account_id,
                "Region": region
            })
    except ClientError as e:
        logging.error(f"Error retrieving Glue jobs: {e}")
    return jobs

def get_msk_inventory():
    msk = boto3.client('kafka')
    account_id, region = get_account_and_region(msk)
    clusters = []
    try:
        for cl in msk.list_clusters().get("ClusterInfoList", []):
            clusters.append({
                "ClusterName": cl.get("ClusterName", ""),
                "ClusterArn": cl.get("ClusterArn", ""),
                "State": cl.get("State", ""),
                "AccountId": account_id,
                "Region": region
            })
    except ClientError as e:
        logging.error(f"Error retrieving MSK clusters: {e}")
    return clusters

def get_directconnect_inventory():
    dc = boto3.client('directconnect')
    account_id, region = get_account_and_region(dc)
    connections = []
    try:
        for conn in dc.describe_connections().get("connections", []):
            connections.append({
                "ConnectionId": conn["connectionId"],
                "ConnectionName": conn.get("connectionName", ""),
                "ConnectionState": conn.get("connectionState", ""),
                "AccountId": account_id,
                "Region": region
            })
    except ClientError as e:
        logging.error(f"Error retrieving Direct Connect connections: {e}")
    return connections

def get_outposts_inventory():
    op = boto3.client('outposts')
    account_id, region = get_account_and_region(op)
    outposts = []
    try:
        for outpost in op.list_outposts().get("Outposts", []):
            outposts.append({
                "OutpostId": outpost["OutpostId"],
                "Name": outpost.get("Name", ""),
                "SiteId": outpost.get("SiteId", ""),
                "AccountId": account_id,
                "Region": region
            })
    except ClientError as e:
        logging.error(f"Error retrieving Outposts: {e}")
    return outposts

def get_servicecatalog_inventory():
    sc = boto3.client('servicecatalog')
    account_id, region = get_account_and_region(sc)
    products = []
    try:
        paginator = sc.get_paginator('search_products_as_admin')
        for page in paginator.paginate():
            for prod in page.get("ProductViewDetails", []):
                products.append({
                    "ProductId": prod.get("ProductViewSummary", {}).get("ProductId", ""),
                    "Name": prod.get("ProductViewSummary", {}).get("Name", ""),
                    "AccountId": account_id,
                    "Region": region
                })
    except ClientError as e:
        logging.error(f"Error retrieving Service Catalog products: {e}")
    return products

if __name__ == "__main__":
    main()
