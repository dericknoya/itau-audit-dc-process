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

DMO_PREFIXES_TO_EXCLUDE = ('ssot', 'unified', 'individual', 'einstein', 'segment_membership', 'aa_', 'aal_')

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
        print(f"❌ ERRO DE AUTENTicação: Arquivo de chave privada não encontrado em '{private_key_file}'")
    except Exception as e:
        print(f"❌ ERRO DE AUTENTicação: {e}")
    print("🚫  A análise não pode continuar devido à falha na autenticação.")
    return False

# --- 2. Carregamento e Preparação dos Dados ---

def load_data_from_csv(files_to_load):
    print("\n📂 Carregando arquivos CSV do diretório 'dataExtract' para análise...")
    dataframes = {}
    input_directory = "dataExtract"
    for name, path in files_to_load.items():
        try:
            df = pd.read_csv(os.path.join(input_directory, path), low_memory=False)
            df.columns = df.columns.str.lower()
            if name.startswith("activations"):
                if "activations" not in dataframes: dataframes["activations"] = []
                dataframes["activations"].append(df)
            else:
                dataframes[name] = df
        except FileNotFoundError:
            print(f"   - ⚠️  AVISO: Arquivo '{path}' não encontrado. Será ignorado.")
            dataframes[name] = pd.DataFrame()

    if "activations" in dataframes and isinstance(dataframes["activations"], list):
        if dataframes["activations"]:
            dataframes["activations"] = pd.concat(dataframes["activations"], ignore_index=True)
            print(f"   - LOG: Arquivos de ativação unificados totalizando {len(dataframes['activations'])} linhas.")
        else:
            dataframes["activations"] = pd.DataFrame()
            
    print("✅  Carregamento de arquivos concluído!\n")
    return dataframes

def extract_fields_from_segments(segments_df):
    used_fields = set()
    criteria_columns = ['includecriteria', 'excludecriteria']
    regex_pattern = r'"objectapiname"\s*:\s*"([^"]+)"\s*,\s*"fieldapiname"\s*:\s*"([^"]+)"'

    for _, row in segments_df.iterrows():
        for col in criteria_columns:
            json_str = str(row[col]).lower()
            if pd.isna(json_str): continue
            
            matches = re.findall(regex_pattern, json_str)
            for dmo, field in matches:
                used_fields.add((dmo, field))
                
    return used_fields


def get_all_dmo_fields(dmos_df, dmo_details_df):
    if dmos_df.empty or 'id' not in dmos_df.columns:
        print("❌ ERRO: 'DataModelObjects.csv' vazio ou sem a coluna 'id'.")
        return pd.DataFrame()
    if dmo_details_df.empty or 'id' not in dmo_details_df.columns:
        print("   - ⚠️  AVISO: 'DataModelObjectsDetails.csv' vazio ou sem a coluna 'id'.")
        dmo_details_df = pd.DataFrame(columns=['id', 'createddate', 'createdbyid'])

    details_subset = dmo_details_df[['id', 'createddate', 'createdbyid']]
    dmos_with_details = pd.merge(dmos_df, details_subset, on='id', how='left')
    
    all_fields_df = dmos_with_details.rename(columns={
        'name': 'dmo_name', 'fields.name': 'field_name',
        'fields.label': 'field_label', 'id': 'dmo_id'
    })
    
    required_cols = ['dmo_name', 'field_name', 'field_label', 'label', 'createddate', 'createdbyid', 'dmo_id']
    for col in required_cols:
        if col not in all_fields_df.columns: all_fields_df[col] = None
            
    return all_fields_df[required_cols]


def get_fields_if_columns_exist(df, entity_col, field_col, source_name):
    if df.empty: return set()
    if entity_col in df.columns and field_col in df.columns:
        df_filtered = df.dropna(subset=[entity_col, field_col])
        return set( (str(row[0]).lower(), str(row[1]).lower()) for _, row in df_filtered[[entity_col, field_col]].iterrows())
    else:
        print(f"   - ⚠️  AVISO: Colunas '{entity_col}' e/ou '{field_col}' não encontradas em {source_name}.")
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
        "activations": "ActivationDetails.csv"
    }
    
    dfs = load_data_from_csv(files_to_load)

    print("🏁 Iniciando fase de análise de campos de DMOs...")

    ci_fields = get_fields_if_columns_exist(dfs.get('cis_expression'), 'expression.table', 'expression.field', "CIExpression.csv")
    print(f"   - LOG: Encontrados {len(ci_fields)} campos únicos em Calculated Insights.")
    
    activation_fields = get_fields_if_columns_exist(dfs.get('activations'), 'attributesconfig.attributes.entityname', 'attributesconfig.attributes.name', "Activation*.csv")
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
    if not users_df.empty and 'id' in users_df.columns:
        all_fields_df = pd.merge(all_fields_df, users_df[['id', 'name']], left_on='createdbyid', right_on='id', how='left').rename(columns={'name': 'created_by_name'}).drop(columns=['id'])
    else:
        all_fields_df['created_by_name'] = None
    
    mkt_fields_df = dfs.get("mkt_fields", pd.DataFrame())
    if not mkt_fields_df.empty and 'mktdatamodelobjectid' in mkt_fields_df.columns:
        mkt_fields_subset = mkt_fields_df.rename(columns={'id': 'deletion_identifier'})
        # Normaliza nomes de campo para o merge
        mkt_fields_subset['developername'] = mkt_fields_subset['developername'].str.lower()
        all_fields_df['field_name_lower'] = all_fields_df['field_name'].str.lower()
        all_fields_df = pd.merge(all_fields_df, mkt_fields_subset, left_on=['dmo_id', 'field_name_lower'], right_on=['mktdatamodelobjectid', 'developername'], how='left').drop(columns=['field_name_lower'])
    else:
        all_fields_df['deletion_identifier'] = None

    print("\n   - LOG: Iniciando filtros de exclusão...")
    
    # --- INÍCIO DA CORREÇÃO DEFINITIVA NA EXCLUSÃO DE CHAVES ---
    print("   - LOG: Iniciando exclusão de campos de Chave Primária por convenção de nome...")
    all_fields_df['field_name_lower'] = all_fields_df['field_name'].astype(str).str.lower()
    
    kq_fields = set(all_fields_df[all_fields_df['field_name_lower'].str.startswith('kq_', na=False)]['field_name_lower'])
    
    main_pk_fields = set()
    for kq_field in kq_fields:
        main_pk_fields.add(kq_field.replace('kq_', '', 1))
        
    pk_fields_to_exclude = kq_fields.union(main_pk_fields)
    print(f"   - LOG: Encontrados {len(pk_fields_to_exclude)} campos de Chave Primária para excluir (Ex: {list(pk_fields_to_exclude)[:5]}).")
    
    initial_field_count = len(all_fields_df)
    all_fields_df = all_fields_df[~all_fields_df['field_name_lower'].isin(pk_fields_to_exclude)]
    all_fields_df.drop(columns=['field_name_lower'], inplace=True)
    print(f"   - LOG: {initial_field_count - len(all_fields_df)} campos de Chave Primária removidos.")
    # --- FIM DA CORREÇÃO DEFINITIVA NA EXCLUSÃO DE CHAVES ---

    print(f"   - LOG: Excluindo {len(STATIC_FIELDS_TO_EXCLUDE)} campos de sistema estáticos.")
    initial_field_count = len(all_fields_df)
    all_fields_df['field_name_lower'] = all_fields_df['field_name'].astype(str).str.lower()
    all_fields_df = all_fields_df[~all_fields_df['field_name_lower'].isin(STATIC_FIELDS_TO_EXCLUDE)]
    all_fields_df.drop(columns=['field_name_lower'], inplace=True)
    print(f"   - LOG: {initial_field_count - len(all_fields_df)} campos de sistema estáticos removidos.")
        
    print(f"\n   - Aplicando filtro para excluir DMOs com prefixos: {DMO_PREFIXES_TO_EXCLUDE}")
    all_fields_df['dmo_name'] = all_fields_df['dmo_name'].astype(str)
    all_fields_df = all_fields_df[~all_fields_df['dmo_name'].str.lower().str.startswith(DMO_PREFIXES_TO_EXCLUDE)]
    print(f"   - DMOs restantes para análise: {len(all_fields_df['dmo_name'].unique())}.")
        
    all_fields_df['createddate_dt'] = pd.to_datetime(all_fields_df['createddate'], errors='coerce')

    records = []
    print("   - Classificando cada campo...")
    for _, row in all_fields_df.iterrows():
        check_tuple = (str(row['dmo_name']).lower(), str(row['field_name']).lower())
        is_directly_used = check_tuple in all_used_fields
        is_in_grace_period = not pd.isna(row['createddate_dt']) and (TODAY - row['createddate_dt']) <= timedelta(days=90)
        status = "Utilizado" if is_directly_used or is_in_grace_period else "Não Utilizado"

        records.append({
            'API_Name': row['dmo_name'], 'Label': row['label'],
            'Field_API_Name': row['field_name'], 'Field_Label': row['field_label'],
            'CreatedDate': row['createddate_dt'].strftime('%Y-%m-%d') if not pd.isna(row['createddate_dt']) else 'N/A',
            'CreatedById': row['createdbyid'],
            'CREATED_BY_NAME': row.get('created_by_name'),
            'DELETION_IDENTIFIER': row.get('deletion_identifier'),
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