import pandas as pd
import matplotlib.pyplot as plt
import os
import glob

# Diretórios
csv_dir = 'csv'
output_dir = 'graficos'
os.makedirs(output_dir, exist_ok=True)

# Função para identificar produto AWS pelo nome do arquivo
def identificar_produto(nome_arquivo):
    nome = nome_arquivo.lower()
    produtos = [
        'acm', 'apigateway', 'athena', 'backup', 'cloudformation', 'cloudfront',
        'cloudwatch_alarms', 'cloudwatch_log_groups', 'codebuild', 'codepipeline',
        'cost_explorer', 'directconnect', 'docdb', 'dynamodb', 'ebs', 'ec2', 'ec', 'ec_keypair',
        'ec_sg', 'ecr', 'efs', 'eks', 'elasticache', 'elastic_beanstalk', 'elastic_ips',
        'elbv2', 'elbv', 'glue', 'iam_roles', 'iam_users', 'kms', 'lambda', 'organizations',
        'rds', 'route53_records',  # deve estar antes de route53_zones, route_zones e route_records
        'route53_zones',
        'route_zones',
        'route_records', 'secrets_manager', 'sns', 's3', 'spot',
        'sqs', 'ssm', 'stepfunctions', 'vpc', 'waf'
    ]
    for produto in produtos:
        if produto in nome:
            return produto.upper()
    return 'DESCONHECIDO'

# Mapeamento de colunas relevantes para cada produto
colunas_relevantes = {
    'EC2': ['InstanceType', 'OS', 'Region'],
    'RDS': ['Engine', 'EngineVersion', 'AllocatedStorageGiB'],
    'ELB': ['Type', 'State'],
    'ELBV2': ['Type'],
    'EBS': ['VolumeType', 'State'],
    'ECR': ['Region'],
    'EFS': ['PerformanceMode', 'ThroughputMode'],
    'LAMBDA': ['Runtime', 'Region'],
    'DYNAMODB': ['Region'],
    'SNS': ['Region'],
    'SQS': ['Region'],
    'VPC': ['CidrBlock', 'Region', 'State', 'IsDefault'],
    'GLUE': ['Region'],
    'EKS': ['Version'],
    'CLOUDFRONT': ['Region'],
    'CLOUDFORMATION': ['Region'],
    'COST_EXPLORER': ['Region'],
    'BACKUP': ['Region'],
    'APIGATEWAY': ['Region'],
    'ATHENA': ['Region'],
    'DOCDB': ['Region'],
    'ELASTICACHE': ['Engine', 'Region'],
    'ELASTIC_BEANSTALK': ['Region'],
    'ELASTIC_IPS': ['Region'],
    'IAM_ROLES': ['Region'],
    'IAM_USERS': ['Region'],
    'KMS': ['Region'],
    'ORGANIZATIONS': ['Region'],
    'SECRETS_MANAGER': ['Region'],
    'SPOT': ['Region'],
    'SSM': ['Region'],
    'STEPFUNCTIONS': ['Region'],
    'WAF': ['Region'],
    'ACM': ['Region'],
    'CLOUDWATCH_ALARMS': ['Region'],
    'CLOUDWATCH_LOG_GROUPS': ['Region'],
    'CODEBUILD': ['Region'],
    'CODEPIPELINE': ['Region'],
    'DIRECTCONNECT': ['Region'],
    'EC_KEYPAIR': ['Region'],
    'EC_SG': ['Region'],
    'S3': ['Region', 'TotalSizeBytes'],
    'ROUTE53_RECORDS': ['Region', 'Name', 'TTL', 'Type'],
    'ROUTE53_ZONES': ['Region', 'Name', 'Id', 'PrivateZone', 'ResourceRecordSetCount'],
    # 'ROUTE_RECORDS': ['Region'],  # Removido
    # 'ROUTE_ZONES': ['Region'],    # Removido
}

# Para cada arquivo CSV na pasta /csv
for csv_file in glob.glob(os.path.join(csv_dir, '*.csv')):
    df = pd.read_csv(csv_file)
    df.columns = df.columns.str.strip()
    base_name = os.path.splitext(os.path.basename(csv_file))[0]
    produto = identificar_produto(base_name)

    print(f'Arquivo: {base_name} | Produto AWS: {produto}')
    print(f'Colunas disponíveis: {list(df.columns)}')

    # Caso especial para S3: gráficos de barras para quantidade de S3, TotalSizeBytes, somatória e valores zero
    if produto == 'S3':
        # Gráfico de barras: quantidade de buckets por região
        if 'Region' in df.columns:
            plt.figure(figsize=(10, 5))
            region_counts = df['Region'].value_counts().sort_values(ascending=False)
            region_counts.plot(kind='bar', color=plt.cm.Pastel1.colors)
            plt.title(f'S3 - Quantidade de Buckets por Região\n({base_name})')
            plt.xlabel('Região')
            plt.ylabel('Quantidade de Buckets')
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'{base_name}_s3_quantidade_por_regiao.png'))
            plt.close()

        # Gráfico de barras: distribuição dos tamanhos dos buckets (em GB)
        if 'TotalSizeBytes' in df.columns:
            df_valid = df.dropna(subset=['TotalSizeBytes'])
            df_valid['TotalSizeBytes'] = pd.to_numeric(df_valid['TotalSizeBytes'], errors='coerce').fillna(0)
            plt.figure(figsize=(12, 6))
            (df_valid['TotalSizeBytes'] / (1024 ** 3)).value_counts(bins=20, sort=False).plot(
                kind='bar', color='skyblue', edgecolor='black'
            )
            plt.title(f'S3 - Distribuição do Tamanho dos Buckets (GB)\n({base_name})')
            plt.xlabel('Faixa de Tamanho do Bucket (GB)')
            plt.ylabel('Quantidade de Buckets')
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'{base_name}_s3_tamanho_buckets_bar.png'))
            plt.close()

            # Somatória de TotalSizeBytes
            soma_total = df_valid['TotalSizeBytes'].sum()
            print(f"Somatória total de armazenamento S3: {soma_total / (1024 ** 3):.2f} GB")

            # Gráfico de barras: quantidade de buckets com TotalSizeBytes = 0
            zeros = (df_valid['TotalSizeBytes'] == 0).sum()
            plt.figure(figsize=(4, 4))
            plt.bar(['TotalSizeBytes = 0', 'TotalSizeBytes > 0'], [zeros, len(df_valid) - zeros], color=['red', 'green'])
            plt.title(f'S3 - Buckets com TotalSizeBytes = 0\n({base_name})')
            plt.ylabel('Quantidade de Buckets')
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'{base_name}_s3_total_size_zero_bar.png'))
            plt.close()

            print(f"Quantidade de buckets com TotalSizeBytes = 0: {zeros}")

            # Quantidade total de buckets
            print(f"Quantidade total de buckets S3: {len(df)}")

        continue

    # Caso especial para VPC: análise de CidrBlock, duplicidade e outras informações relevantes
    if produto == 'VPC' and 'CidrBlock' in df.columns:
        # Gráfico de quantidade de VPCs por CidrBlock
        plt.figure(figsize=(12, 6))
        cidr_counts = df['CidrBlock'].value_counts().sort_values(ascending=False)
        cidr_counts.plot(kind='bar', color=plt.cm.Paired.colors)
        plt.title(f'VPC - Quantidade por CidrBlock\n({base_name})')
        plt.xlabel('CidrBlock')
        plt.ylabel('Quantidade de VPCs')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f'{base_name}_vpc_por_cidrblock.png'))
        plt.close()

        # Gráfico de duplicidade de CidrBlock
        duplicados = cidr_counts[cidr_counts > 1]
        if not duplicados.empty:
            plt.figure(figsize=(10, 5))
            duplicados.plot(kind='bar', color=plt.cm.Set2.colors)
            plt.title(f'VPC - CidrBlocks Duplicados\n({base_name})')
            plt.xlabel('CidrBlock')
            plt.ylabel('Quantidade de VPCs')
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'{base_name}_vpc_cidrblock_duplicados.png'))
            plt.close()

        # Gráfico de VPCs por região, se existir coluna Region
        if 'Region' in df.columns:
            plt.figure(figsize=(8, 5))
            region_counts = df['Region'].value_counts().sort_values(ascending=False)
            region_counts.plot(kind='bar', color=plt.cm.Pastel1.colors)
            plt.title(f'VPC - Quantidade por Região\n({base_name})')
            plt.xlabel('Region')
            plt.ylabel('Quantidade de VPCs')
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'{base_name}_vpc_por_region.png'))
            plt.close()

        # Gráfico de VPCs padrão (IsDefault), se existir coluna IsDefault
        if 'IsDefault' in df.columns:
            plt.figure(figsize=(5, 5))
            default_counts = df['IsDefault'].value_counts()
            default_counts.plot(kind='pie', autopct='%1.1f%%', startangle=90, colors=plt.cm.Set3.colors)
            plt.title(f'VPC - Proporção de VPCs Default\n({base_name})')
            plt.ylabel('')
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'{base_name}_vpc_isdefault_pie.png'))
            plt.close()
        continue

    # Caso especial para ACM: quantidade de CertificateArn por DomainName
    if produto == 'ACM' and 'DomainName' in df.columns and 'CertificateArn' in df.columns:
        plt.figure(figsize=(10, 6))
        domain_counts = df.groupby('DomainName')['CertificateArn'].count().sort_values(ascending=False)
        domain_counts.plot(kind='bar', color=plt.cm.Paired.colors)
        plt.title(f'ACM - Quantidade de Certificates por DomainName\n({base_name})')
        plt.xlabel('DomainName')
        plt.ylabel('Quantidade de Certificates')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f'{base_name}_certificates_por_domainname.png'))
        plt.close()
        continue

    # Caso especial para APIGATEWAY: quantidade de APIs por AccountId
    if produto == 'APIGATEWAY' and 'AccountId' in df.columns and 'Id' in df.columns:
        plt.figure(figsize=(10, 6))
        api_counts = df.groupby('AccountId')['Id'].count().sort_values(ascending=False)
        api_counts.plot(kind='bar', color=plt.cm.Set2.colors)
        plt.title(f'APIGateway - Quantidade de APIs por AccountId\n({base_name})')
        plt.xlabel('AccountId')
        plt.ylabel('Quantidade de APIs')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f'{base_name}_apis_por_accountid.png'))
        plt.close()
        continue

    # Caso especial para EC2: quantidade de EC2 por InstanceType, OS e Region
    if produto == 'EC2':
        if 'InstanceType' in df.columns:
            plt.figure(figsize=(12, 6))
            inst_counts = df['InstanceType'].value_counts().sort_values(ascending=False)
            inst_counts.plot(kind='bar', color=plt.cm.Paired.colors)
            plt.title(f'EC2 - Quantidade por InstanceType\n({base_name})')
            plt.xlabel('InstanceType')
            plt.ylabel('Quantidade de Instâncias')
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'{base_name}_ec2_por_instancetype.png'))
            plt.close()
        if 'OS' in df.columns:
            plt.figure(figsize=(8, 6))
            os_counts = df['OS'].value_counts().sort_values(ascending=False)
            os_counts.plot(kind='bar', color=plt.cm.Set3.colors)
            plt.title(f'EC2 - Quantidade por OS\n({base_name})')
            plt.xlabel('OS')
            plt.ylabel('Quantidade de Instâncias')
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'{base_name}_ec2_por_os.png'))
            plt.close()
        if 'Region' in df.columns:
            plt.figure(figsize=(8, 6))
            reg_counts = df['Region'].value_counts().sort_values(ascending=False)
            reg_counts.plot(kind='bar', color=plt.cm.Pastel1.colors)
            plt.title(f'EC2 - Quantidade por Region\n({base_name})')
            plt.xlabel('Region')
            plt.ylabel('Quantidade de Instâncias')
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'{base_name}_ec2_por_region.png'))
            plt.close()
        continue

    # Caso especial para EKS: quantidade de clusters por Version
    if produto == 'EKS' and 'Version' in df.columns:
        plt.figure(figsize=(8, 6))
        version_counts = df['Version'].value_counts().sort_index()
        version_counts.plot(kind='bar', color=plt.cm.Set2.colors)
        plt.title(f'EKS - Quantidade de Clusters por Version\n({base_name})')
        plt.xlabel('Version')
        plt.ylabel('Quantidade de Clusters')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f'{base_name}_eks_por_version.png'))
        plt.close()
        continue

    # Caso especial para RDS: quantidade de RDS por Engine, EngineVersion e AllocatedStorageGiB
    if produto == 'RDS':
        if 'Engine' in df.columns:
            plt.figure(figsize=(10, 6))
            engine_counts = df['Engine'].value_counts().sort_values(ascending=False)
            engine_counts.plot(kind='bar', color=plt.cm.Paired.colors)
            plt.title(f'RDS - Quantidade por Engine\n({base_name})')
            plt.xlabel('Engine')
            plt.ylabel('Quantidade de RDS')
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'{base_name}_rds_por_engine.png'))
            plt.close()
        if 'EngineVersion' in df.columns:
            plt.figure(figsize=(12, 6))
            version_counts = df['EngineVersion'].value_counts().sort_index()
            version_counts.plot(kind='bar', color=plt.cm.Set2.colors)
            plt.title(f'RDS - Quantidade por EngineVersion\n({base_name})')
            plt.xlabel('EngineVersion')
            plt.ylabel('Quantidade de RDS')
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'{base_name}_rds_por_engineversion.png'))
            plt.close()
        if 'AllocatedStorageGiB' in df.columns:
            plt.figure(figsize=(12, 6))
            storage_counts = df['AllocatedStorageGiB'].value_counts().sort_index()
            storage_counts.plot(kind='bar', color=plt.cm.Pastel1.colors)
            plt.title(f'RDS - Quantidade por AllocatedStorageGiB\n({base_name})')
            plt.xlabel('AllocatedStorageGiB')
            plt.ylabel('Quantidade de RDS')
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'{base_name}_rds_por_allocatedstoragegib.png'))
            plt.close()
        continue

    # Caso especial para ELBV2: quantidade de tipos existentes
    if produto == 'ELBV2' and 'Type' in df.columns:
        plt.figure(figsize=(7, 5))
        type_counts = df['Type'].value_counts()
        type_counts.plot(kind='bar', color=plt.cm.Paired.colors)
        plt.title(f'ELBV2 - Quantidade por Tipo\n({base_name})')
        plt.xlabel('Tipo')
        plt.ylabel('Quantidade')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f'{base_name}_elbv2_por_tipo.png'))
        plt.close()
        continue

    # Caso especial para ROUTE53_RECORDS: gráficos de barras por Name, TTL e Type, e outras informações relevantes
    if produto == 'ROUTE53_RECORDS':
        # Gráfico de barras: quantidade de registros por Name (top 20)
        if 'Name' in df.columns:
            plt.figure(figsize=(14, 6))
            name_counts = df['Name'].value_counts().head(20)
            name_counts.plot(kind='bar', color=plt.cm.Paired.colors)
            plt.title(f'Route53 Records - Top 20 Names\n({base_name})')
            plt.xlabel('Name')
            plt.ylabel('Quantidade de Registros')
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'{base_name}_route53_records_por_name.png'))
            plt.close()

        # Gráfico de barras: quantidade de registros por TTL
        if 'TTL' in df.columns:
            plt.figure(figsize=(10, 5))
            ttl_counts = df['TTL'].value_counts().sort_index()
            ttl_counts.plot(kind='bar', color=plt.cm.Set2.colors)
            plt.title(f'Route53 Records - Quantidade por TTL\n({base_name})')
            plt.xlabel('TTL')
            plt.ylabel('Quantidade de Registros')
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'{base_name}_route53_records_por_ttl.png'))
            plt.close()

        # Gráfico de barras: quantidade de registros por Type
        if 'Type' in df.columns:
            plt.figure(figsize=(8, 5))
            type_counts = df['Type'].value_counts()
            type_counts.plot(kind='bar', color=plt.cm.Pastel1.colors)
            plt.title(f'Route53 Records - Quantidade por Type\n({base_name})')
            plt.xlabel('Type')
            plt.ylabel('Quantidade de Registros')
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'{base_name}_route53_records_por_type.png'))
            plt.close()

        # Informação relevante: quantidade total de registros
        print(f"Quantidade total de registros Route53: {len(df)}")

        # Informação relevante: nomes de registros duplicados
        if 'Name' in df.columns:
            duplicados = df['Name'].value_counts()
            duplicados = duplicados[duplicados > 1]
            if not duplicados.empty:
                print("Registros duplicados (Name):")
                print(duplicados)

        # Informação relevante: tipos de registros únicos
        if 'Type' in df.columns:
            tipos_unicos = df['Type'].unique()
            print(f"Tipos de registros encontrados: {', '.join(map(str, tipos_unicos))}")
        continue

    # Caso especial para ROUTE53_ZONES: gráficos de barras por Region, Name e Id, e outras informações relevantes
    if produto == 'ROUTE53_ZONES':
        # Gráfico de barras: quantidade de zonas por Region
        if 'Region' in df.columns:
            plt.figure(figsize=(10, 5))
            region_counts = df['Region'].value_counts().sort_values(ascending=False)
            region_counts.plot(kind='bar', color=plt.cm.Pastel1.colors)
            plt.title(f'Route53 Zones - Quantidade por Region\n({base_name})')
            plt.xlabel('Region')
            plt.ylabel('Quantidade de Zonas')
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'{base_name}_route53_zones_por_region.png'))
            plt.close()

        # Gráfico de barras: quantidade de zonas por Name (top 20)
        if 'Name' in df.columns:
            plt.figure(figsize=(14, 6))
            name_counts = df['Name'].value_counts().head(20)
            name_counts.plot(kind='bar', color=plt.cm.Paired.colors)
            plt.title(f'Route53 Zones - Top 20 Names\n({base_name})')
            plt.xlabel('Name')
            plt.ylabel('Quantidade de Zonas')
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'{base_name}_route53_zones_por_name.png'))
            plt.close()

        # Gráfico de barras: quantidade de zonas por Id
        if 'Id' in df.columns:
            plt.figure(figsize=(10, 5))
            id_counts = df['Id'].value_counts()
            id_counts.plot(kind='bar', color=plt.cm.Set2.colors)
            plt.title(f'Route53 Zones - Quantidade por Id\n({base_name})')
            plt.xlabel('Id')
            plt.ylabel('Quantidade de Zonas')
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'{base_name}_route53_zones_por_id.png'))
            plt.close()

        # Gráfico de barras: quantidade de zonas por PrivateZone
        if 'PrivateZone' in df.columns:
            plt.figure(figsize=(6, 4))
            private_counts = df['PrivateZone'].value_counts()
            private_counts.plot(kind='bar', color=['orange', 'blue'])
            plt.title(f'Route53 Zones - Quantidade por PrivateZone\n({base_name})')
            plt.xlabel('PrivateZone')
            plt.ylabel('Quantidade de Zonas')
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'{base_name}_route53_zones_por_privatezone.png'))
            plt.close()

        # Gráfico de barras: quantidade de zonas por ResourceRecordSetCount (top 20)
        if 'ResourceRecordSetCount' in df.columns:
            plt.figure(figsize=(12, 6))
            rrcounts = df['ResourceRecordSetCount'].value_counts().head(20)
            # Corrigido: usar uma lista de cores do colormap, não .colors
            colors = [plt.cm.Greens(i / max(len(rrcounts) - 1, 1)) for i in range(len(rrcounts))]
            rrcounts.plot(kind='bar', color=colors)
            plt.title(f'Route53 Zones - Top 20 ResourceRecordSetCount\n({base_name})')
            plt.xlabel('ResourceRecordSetCount')
            plt.ylabel('Quantidade de Zonas')
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'{base_name}_route53_zones_por_rrcount.png'))
            plt.close()

        # Informação relevante: quantidade total de zonas
        print(f"Quantidade total de zonas Route53: {len(df)}")

        # Informação relevante: nomes de zonas duplicadas
        if 'Name' in df.columns:
            duplicados = df['Name'].value_counts()
            duplicados = duplicados[duplicados > 1]
            if not duplicados.empty:
                print("Zonas duplicadas (Name):")
                print(duplicados)

        continue

    # Se o produto for conhecido e houver colunas relevantes
    if produto in colunas_relevantes:
        for coluna in colunas_relevantes[produto]:
            if coluna in df.columns:
                # Só faz gráfico de pizza para colunas categóricas
                if pd.api.types.is_numeric_dtype(df[coluna]):
                    continue
                plt.figure(figsize=(7, 7))
                valores = df[coluna].value_counts()
                if len(valores) == 0:
                    continue
                if coluna.lower() in ['state', 'status']:
                    colors = plt.cm.Pastel1(range(len(valores)))
                elif coluna.lower() in ['region']:
                    colors = plt.cm.Set3(range(len(valores)))
                elif coluna.lower() in ['instancetype', 'dbinstanceclass', 'volumetype', 'type']:
                    colors = plt.cm.Paired(range(len(valores)))
                else:
                    colors = plt.cm.tab20(range(len(valores)))
                valores.plot(
                    kind='pie',
                    autopct='%1.1f%%',
                    startangle=90,
                    colors=colors,
                    legend=False
                )
                plt.title(f'{produto} - Distribuição por {coluna}\n({base_name})')
                plt.ylabel('')
                plt.tight_layout()
                plt.savefig(os.path.join(output_dir, f'{base_name}_{coluna.lower()}_pie.png'))
                plt.close()
    else:
        print(f'Produto AWS não identificado ou sem colunas relevantes para geração de gráficos.\n({base_name})')