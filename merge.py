import pandas as pd
import glob
import os
import re

# Use o diretório corrente (ajuste: não usar '/')
diretorio = '.'  # Diretório corrente

# Não mude de diretório globalmente, apenas use caminhos relativos
# os.chdir(diretorio)  # Removido

# Lista de produtos AWS conforme README.md (nomes simplificados para busca no nome do arquivo)
produtos = [
    "ec2", "rds", "s3", "lambda", "eks", "spot", "iam_users", "iam_roles", "cloudfront",
    "dynamodb", "elbv2", "sns", "sqs", "cloudformation", "ecr", "docdb", "redshift",
    "elasticache", "efs", "fsx", "glacier", "backup", "ebs", "vpc", "ec2_sg", "ec2_keypair",
    "acm", "route53_zones", "route53_records", "elastic_beanstalk", "elastic_ips", "kms",
    "secrets_manager", "ssm", "stepfunctions", "apigateway", "appsync", "codebuild",
    "codepipeline", "codedeploy", "cloudwatch_alarms", "cloudwatch_log_groups",
    "organizations", "cost_explorer", "waf", "shield", "sagemaker", "athena", "glue",
    "msk", "directconnect", "outposts", "servicecatalog", "macie", "guardduty", "detective",
    "resource_groups", "resource_tag_editor"
]

# Cria um dicionário para armazenar arquivos por produto
arquivos_por_produto = {produto: [] for produto in produtos}

# Liste todos os arquivos CSV no diretório corrente
arquivos_csv = glob.glob(os.path.join(diretorio, '*.csv'))

# Associa cada arquivo ao produto correspondente
for arquivo in arquivos_csv:
    nome_arquivo = os.path.basename(arquivo).lower()
    for produto in produtos:
        # Busca padrão _produto_ ou _produto.csv ou produto_ ou produto.csv
        # Ajuste: garantir que o padrão _produto_ seja encontrado em qualquer parte do nome
        if re.search(rf'(_{produto}_|_{produto}\.csv|^{produto}_|^{produto}\.csv|_{produto}$|^{produto}$)', nome_arquivo):
            arquivos_por_produto[produto].append(arquivo)
            break

# Para cada produto, concatena os arquivos e salva um novo arquivo
for produto, arquivos in arquivos_por_produto.items():
    lista_df = []
    for arquivo in arquivos:
        try:
            df = pd.read_csv(arquivo)
            lista_df.append(df)
        except Exception as e:
            print(f"Erro ao ler {arquivo}: {e}")
    if lista_df:
        df_concatenado = pd.concat(lista_df, ignore_index=True, sort=True)
        nome_saida = f"{produto}.csv"  # Salva com o nome do produto AWS
        df_concatenado.to_csv(nome_saida, index=False)
        print(f"Arquivo unificado salvo como '{nome_saida}' com {len(df_concatenado)} linhas.")
    # else:
    #     print(f"Nenhum arquivo encontrado para o produto {produto}.")
