import boto3
import logging
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def get_ec2_inventory():
    ec2 = boto3.client('ec2')
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
                        "Name": next((tag["Value"] for tag in instance.get("Tags", []) if tag["Key"] == "Name"), "N/A")
                    }
                    instances.append(instance_info)
    except ClientError as e:
        logging.error(f"Error retrieving EC2 instances: {e}")
    return instances

def get_rds_inventory():
    rds = boto3.client('rds')
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
                    "Endpoint": instance["Endpoint"]["Address"]
                }
                rds_instances.append(rds_instance_info)
    except ClientError as e:
        logging.error(f"Error retrieving RDS instances: {e}")
    return rds_instances

def get_s3_inventory():
    s3 = boto3.client('s3')
    s3_buckets = []
    try:
        response = s3.list_buckets()
        for bucket in response["Buckets"]:
            s3_bucket_info = {
                "Name": bucket["Name"],
                "CreationDate": bucket["CreationDate"].strftime("%Y-%m-%d %H:%M:%S")
            }
            s3_buckets.append(s3_bucket_info)
    except ClientError as e:
        logging.error(f"Error retrieving S3 buckets: {e}")
    return s3_buckets

def get_lambda_inventory():
    lambda_client = boto3.client('lambda')
    lambda_functions = []
    try:
        paginator = lambda_client.get_paginator('list_functions')
        for page in paginator.paginate():
            for function in page["Functions"]:
                lambda_function_info = {
                    "FunctionName": function["FunctionName"],
                    "Runtime": function["Runtime"],
                    "LastModified": function["LastModified"],
                    "CodeSize": function["CodeSize"]
                }
                lambda_functions.append(lambda_function_info)
    except ClientError as e:
        logging.error(f"Error retrieving Lambda functions: {e}")
    return lambda_functions

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

    logging.info("Getting RDS instances inventory...")
    rds_inventory = get_rds_inventory()
    print_inventory(rds_inventory, "RDS Instances Inventory")

    logging.info("Getting S3 buckets inventory...")
    s3_inventory = get_s3_inventory()
    print_inventory(s3_inventory, "S3 Buckets Inventory")

    logging.info("Getting Lambda functions inventory...")
    lambda_inventory = get_lambda_inventory()
    print_inventory(lambda_inventory, "Lambda Functions Inventory")

if __name__ == "__main__":
    main()
