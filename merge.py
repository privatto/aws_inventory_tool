import pandas as pd
import glob
import os
import re

diretorio = '.'  # Diretório corrente

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

# Padrões exclusivos para evitar sobreposição entre ec2, ec2_sg, ec2_keypair
padroes_produto = {
    "ec2": re.compile(r'(^|[_.-])ec2(_inventory)?(\.csv)?$', re.IGNORECASE),
    "ec2_sg": re.compile(r'(^|[_.-])ec2_sg(_inventory)?(\.csv)?$', re.IGNORECASE),
    "ec2_keypair": re.compile(r'(^|[_.-])ec2_keypair(_inventory)?(\.csv)?$', re.IGNORECASE),
}
# Para os demais produtos, usar o padrão genérico
for produto in produtos:
    if produto not in padroes_produto:
        padroes_produto[produto] = re.compile(rf'(^|[_.-]){produto}(_inventory)?(\.csv)?$', re.IGNORECASE)

# Liste todos os arquivos CSV no diretório corrente
arquivos_csv = glob.glob(os.path.join(diretorio, '*.csv'))

# Para cada produto, concatena apenas os arquivos que pertencem exclusivamente a ele
for produto in produtos:
    padrao = padroes_produto[produto]
    arquivos_produto = [
        arq for arq in arquivos_csv
        if padrao.search(os.path.splitext(os.path.basename(arq))[0])
    ]
    lista_df = []
    for arquivo in arquivos_produto:
        try:
            df = pd.read_csv(arquivo)
            lista_df.append(df)
        except Exception as e:
            print(f"Erro ao ler {arquivo}: {e}")
    if lista_df:
        df_concatenado = pd.concat(lista_df, ignore_index=True, sort=True)
        nome_saida = f"{produto}.csv"
        df_concatenado.to_csv(nome_saida, index=False)
        print(f"Arquivo unificado salvo como '{nome_saida}' com {len(df_concatenado)} linhas.")
