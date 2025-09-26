import pandas as pd
from datetime import datetime, timedelta, timezone
import os
import requests
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import time
from dotenv import load_dotenv
import re

# --- 1. Configuração e Autenticação ---

load_dotenv()
SF_LOGIN_URL = os.getenv("SF_LOGIN_URL", "https://login.salesforce.com")
SF_CLIENT_ID = os.getenv("SF_CLIENT_ID")
SF_USERNAME = os.getenv("SF_USERNAME")
SF_PRIVATE_KEY_FILE = os.getenv("SF_PRIVATE_KEY_FILE", "private.pem")
USE_PROXY = os.getenv("USE_PROXY", "True").lower() == "true"
PROXY_URL = os.getenv("PROXY_URL")
VERIFY_SSL = os.getenv("VERIFY_SSL", "False").lower() == "true"
proxies = {'http': PROXY_URL, 'https': PROXY_URL} if USE_PROXY else None
TODAY = datetime.now(timezone.utc)

DMO_PREFIXES_TO_EXCLUDE = ('iub_','ibb_','ssot', 'unified', 'individual', 'einstein', 'segment_membership', 'aa_', 'aal_')

STATIC_FIELDS_TO_EXCLUDE = {
    'datasource__c', 
    'datasourceobject__c', 
    'internalorganization__c'
}


def authenticate_jwt(login_url, client_id, username, private_key_file):
    print("🔐  Iniciando verificação de autenticação via JWT...")
    try:
        with open(private_key_file, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
        payload = {"iss": client_id, "sub": username, "aud": login_url, "exp": int(time.time()) + 180}
        token = jwt.encode(payload, private_key, algorithm="RS256")
        data = {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": token}
        auth_url = f"{login_url}/services/oauth2/token"
        response = requests.post(auth_url, data=data, proxies=proxies, verify=VERIFY_SSL)
        response.raise_for_status()
        print("✅  Autenticação bem-sucedida. Prosseguindo com a análise dos arquivos locais.")
        return True
    except FileNotFoundError:
        print(f"❌ ERRO DE AUTENTICAÇÃO: Arquivo de chave privada não encontrado em '{private_key_file}'")
    except Exception as e:
        print(f"❌ ERRO DE AUTENTICAÇÃO: {e}")
    print("🚫  A análise não pode continuar devido à falha na autenticação.")
    return False

# --- 2. Carregamento e Preparação dos Dados ---

def load_data_from_csv(files_to_load):
    print("\n📂 Carregando arquivos CSV do diretório 'dataExtract' para análise...")
    dataframes = {}
    input_directory = "dataExtract"
    for name, path in files_to_load.items():
        try:
            if name.startswith("activations"):
                if "activations" not in dataframes:
                    dataframes["activations"] = []
                df = pd.read_csv(os.path.join(input_directory, path), low_memory=False)
                dataframes["activations"].append(df)
            else:
                dataframes[name] = pd.read_csv(os.path.join(input_directory, path), low_memory=False)
        except FileNotFoundError:
            print(f"   - ⚠️  AVISO: Arquivo '{path}' não encontrado no diretório '{input_directory}'. Será ignorado.")
            dataframes[name] = pd.DataFrame()

    if "activations" in dataframes and isinstance(dataframes["activations"], list):
        if dataframes["activations"]:
            dataframes["activations"] = pd.concat(dataframes["activations"], ignore_index=True)
            print(f"   - LOG: Arquivos de ativação unificados totalizando {len(dataframes['activations'])} linhas.")
        else:
            dataframes["activations"] = pd.DataFrame()
            
    print("✅  Carregamento de arquivos concluído!\n")
    return dataframes
    
def normalize_dataframes(dfs):
    """Converte colunas de texto chave para minúsculas para garantir consistência."""
    print("   - LOG: Normalizando dados para análise (convertendo para minúsculas)...")
    
    # Mapeamento de quais colunas normalizar em cada arquivo
    columns_to_normalize = {
        'dmos': ['name', 'fields.name'],
        'cis_expression': ['expression.table', 'expression.field'],
        'activations': ['attributesConfig.attributes.entityName', 'attributesConfig.attributes.name'],
        'mkt_fields': ['DeveloperName', 'KeyQualifierName']
    }

    for df_key, columns in columns_to_normalize.items():
        if df_key in dfs and not dfs[df_key].empty:
            for col in columns:
                if col in dfs[df_key].columns:
                    # Garante que a coluna seja do tipo string antes de aplicar .str
                    dfs[df_key][col] = dfs[df_key][col].astype(str).str.lower()
    return dfs


def extract_fields_from_segments(segments_df):
    used_fields = set()
    criteria_columns = ['IncludeCriteria', 'ExcludeCriteria']
    regex_pattern = r'"objectApiName"\s*:\s*"([^"]+)"\s*,\s*"fieldApiName"\s*:\s*"([^"]+)"'

    for _, row in segments_df.iterrows():
        for col in criteria_columns:
            json_str = row[col]
            if pd.isna(json_str) or not isinstance(json_str, str): continue
            
            # A busca regex já é case-insensitive, mas garantimos a conversão para o set
            matches = re.findall(regex_pattern, json_str, re.IGNORECASE)
            for dmo, field in matches:
                used_fields.add((dmo.lower(), field.lower()))
                
    return used_fields


def get_all_dmo_fields(dmos_df, dmo_details_df):
    if dmos_df.empty or 'id' not in dmos_df.columns:
        print("❌ ERRO: 'DataModelObjects.csv' vazio ou sem a coluna 'id'.")
        return pd.DataFrame()
    if dmo_details_df.empty or 'Id' not in dmo_details_df.columns:
        print("   - ⚠️  AVISO: 'DataModelObjectsDetails.csv' vazio ou sem a coluna 'Id'. As datas de criação não serão preenchidas.")
        dmo_details_df = pd.DataFrame(columns=['Id', 'CreatedDate', 'CreatedById'])

    dmo_details_df = dmo_details_df.rename(columns={'Id': 'id'})
    details_subset = dmo_details_df[['id', 'CreatedDate', 'CreatedById']]
    
    dmos_with_details = pd.merge(dmos_df, details_subset, on='id', how='left')
    
    all_fields_df = dmos_with_details.rename(columns={
        'name': 'DMO_Name',
        'fields.name': 'Field_Name',
        'fields.label': 'Field_Label',
        'id': 'DMO_Id'
    })
    
    required_cols = ['DMO_Name', 'Field_Name', 'Field_Label', 'label', 'CreatedDate', 'CreatedById', 'DMO_Id']
    for col in required_cols:
        if col not in all_fields_df.columns: all_fields_df[col] = None
            
    return all_fields_df[required_cols]


def get_fields_if_columns_exist(df, entity_col, field_col, source_name):
    if df.empty: return set()
    if entity_col in df.columns and field_col in df.columns:
        df_filtered = df.dropna(subset=[entity_col, field_col])
        # Os dados já foram normalizados, então a extração é direta
        return set(tuple(row) for row in df_filtered[[entity_col, field_col]].to_numpy())
    else:
        print(f"   - ⚠️  AVISO: Colunas '{entity_col}' e/ou '{field_col}' não encontradas em {source_name}. Pulando esta fonte.")
        return set()

# --- 3. Lógica Principal de Análise de Campos ---

def main():
    if not authenticate_jwt(SF_LOGIN_URL, SF_CLIENT_ID, SF_USERNAME, SF_PRIVATE_KEY_FILE):
        return
        
    files_to_load = {
        "dmos": "DataModelObjects.csv",
        "dmo_details": "DataModelObjectsDetails.csv",
        "users": "Users.csv",
        "mkt_fields": "MktDataModelField.csv",
        "cis_expression": "CIExpression.csv",
        "segments": "MarketSegment.csv",
        "activations": "ActivationDetails.csv",
    }
    
    dfs = load_data_from_csv(files_to_load)
    dfs = normalize_dataframes(dfs) # Normaliza todos os dados de uma vez

    print("🏁 Iniciando fase de análise de campos de DMOs...")

    ci_fields = get_fields_if_columns_exist(dfs.get('cis_expression'), 'expression.table', 'expression.field', "CIExpression.csv")
    print(f"   - LOG: Encontrados {len(ci_fields)} campos únicos em Calculated Insights.")
    
    activation_fields = get_fields_if_columns_exist(dfs.get('activations'), 'attributesConfig.attributes.entityName', 'attributesConfig.attributes.name', "Activation*.csv")
    print(f"   - LOG: Encontrados {len(activation_fields)} campos únicos em Ativações.")
    
    segment_fields = set()
    segments_df = dfs.get('segments', pd.DataFrame())
    if not segments_df.empty:
         segment_fields = extract_fields_from_segments(segments_df)
    print(f"   - LOG: Encontrados {len(segment_fields)} campos únicos em Segmentos.")

    all_used_fields = ci_fields.union(segment_fields).union(activation_fields)
    print(f"✅ Total de {len(all_used_fields)} pares (DMO, Campo) únicos encontrados em uso.")

    all_fields_df = get_all_dmo_fields(dfs.get("dmos", pd.DataFrame()), dfs.get("dmo_details", pd.DataFrame()))
    if all_fields_df.empty:
        print("Nenhum campo de DMO encontrado para analisar. Encerrando.")
        return
    print(f"\n   - LOG: Total de {len(all_fields_df)} campos de DMO encontrados para análise (antes dos filtros de exclusão).")
        
    users_df = dfs.get("users", pd.DataFrame())
    if not users_df.empty and 'Id' in users_df.columns:
        all_fields_df = pd.merge(all_fields_df, users_df[['Id', 'Name']], left_on='CreatedById', right_on='Id', how='left').rename(columns={'Name': 'CREATED_BY_NAME'}).drop(columns=['Id'])
    else:
        all_fields_df['CREATED_BY_NAME'] = None
    
    mkt_fields_df = dfs.get("mkt_fields", pd.DataFrame())
    if not mkt_fields_df.empty and 'MktDataModelObjectId' in mkt_fields_df.columns:
        mkt_fields_subset = mkt_fields_df.rename(columns={'Id': 'DELETION_IDENTIFIER'})
        all_fields_df = pd.merge(all_fields_df, mkt_fields_subset, left_on=['DMO_Id', 'Field_Name'], right_on=['MktDataModelObjectId', 'DeveloperName'], how='left')
    else:
        all_fields_df['DELETION_IDENTIFIER'] = None

    print("\n   - LOG: Iniciando filtros de exclusão...")
    
    if not mkt_fields_df.empty and 'DeveloperName' in mkt_fields_df.columns and 'KeyQualifierName' in mkt_fields_df.columns:
        kq_field_names = set(mkt_fields_df[mkt_fields_df['DeveloperName'].str.startswith('kq_', na=False)]['DeveloperName'])
        main_pk_field_names = set(mkt_fields_df[mkt_fields_df['KeyQualifierName'].notna()]['DeveloperName'])
        pointed_to_names = set(mkt_fields_df[mkt_fields_df['KeyQualifierName'].notna()]['KeyQualifierName'])
        pk_fields_to_exclude = kq_field_names.union(main_pk_field_names).union(pointed_to_names)
        
        print(f"   - LOG: Encontrados {len(pk_fields_to_exclude)} campos de Chave Primária para excluir.")
        initial_field_count = len(all_fields_df)
        all_fields_df = all_fields_df[~all_fields_df['Field_Name'].isin(pk_fields_to_exclude)]
        print(f"   - LOG: {initial_field_count - len(all_fields_df)} campos de Chave Primária removidos.")
    else:
        print("   - LOG: Colunas para identificar Chaves Primárias não encontradas. Pulando esta exclusão.")

    print(f"   - LOG: Excluindo {len(STATIC_FIELDS_TO_EXCLUDE)} campos de sistema estáticos.")
    initial_field_count = len(all_fields_df)
    all_fields_df = all_fields_df[~all_fields_df['Field_Name'].isin(STATIC_FIELDS_TO_EXCLUDE)]
    print(f"   - LOG: {initial_field_count - len(all_fields_df)} campos de sistema estáticos removidos.")
        
    print(f"\n   - Aplicando filtro para excluir DMOs com prefixos: {DMO_PREFIXES_TO_EXCLUDE}")
    all_fields_df = all_fields_df[~all_fields_df['DMO_Name'].str.startswith(DMO_PREFIXES_TO_EXCLUDE)]
    print(f"   - DMOs restantes para análise: {len(all_fields_df['DMO_Name'].unique())}.")
        
    all_fields_df['CreatedDate_dt'] = pd.to_datetime(all_fields_df['CreatedDate'], errors='coerce')

    records = []
    print("   - Classificando cada campo...")
    for _, row in all_fields_df.iterrows():
        check_tuple = (row['DMO_Name'], row['Field_Name'])
        is_directly_used = check_tuple in all_used_fields
        is_in_grace_period = not pd.isna(row['CreatedDate_dt']) and (TODAY - row['CreatedDate_dt']) <= timedelta(days=90)
        status = "Utilizado" if is_directly_used or is_in_grace_period else "Não Utilizado"

        records.append({
            'API_Name': row['DMO_Name'], 'Label': row['label'],
            'Field_API_Name': row['Field_Name'], 'Field_Label': row['Field_Label'],
            'CreatedDate': row['CreatedDate_dt'].strftime('%Y-m-%d') if not pd.isna(row['CreatedDate_dt']) else 'N/A',
            'CreatedById': row['CreatedById'],
            'CREATED_BY_NAME': row.get('CREATED_BY_NAME'),
            'DELETION_IDENTIFIER': row.get('DELETION_IDENTIFIER'),
            'Status': status
        })
            
    print("\n" + "="*50)
    print("🎉 Análise de campos concluída! Gerando relatórios...")
    
    if not records:
        print("   - ℹ️ Nenhum registro encontrado para gerar relatórios.")
        return
        
    final_df = pd.DataFrame(records).drop_duplicates()
    
    used_df = final_df[final_df['Status'] == 'Utilizado'].copy()
    used_df.drop(columns=['Status', 'DELETION_IDENTIFIER'], inplace=True, errors='ignore')
    used_df.to_csv('audit_campos_utilizados.csv', index=False)
    print(f"   - ✅ Relatório 'audit_campos_utilizados.csv' salvo com {len(used_df)} campos.")
    
    unused_df = final_df[final_df['Status'] == 'Não Utilizado'].copy()
    unused_df.drop(columns=['Status'], inplace=True, errors='ignore')
    unused_df.to_csv('audit_campos_nao_utilizados.csv', index=False)
    print(f"   - ✅ Relatório 'audit_campos_nao_utilizados.csv' salvo com {len(unused_df)} campos.")
        
    print("="*50)
    print("✅ Processo de auditoria de campos finalizado.")
    print("="*50)


if __name__ == "__main__":
    main()