import pandas as pd
from datetime import datetime, timedelta, timezone
import os
import requests
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import time
from dotenv import load_dotenv

# --- 1. Configuração e Autenticação (Sem alterações) ---

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

# --- 2. Carregamento e Preparação dos Dados (Sem alterações) ---

def load_data_from_csv(files_to_load):
    print("\n📂 Carregando arquivos CSV do diretório 'dataExtract' para análise...")
    dataframes = {}
    input_directory = "dataExtract"
    for name, path in files_to_load.items():
        try:
            full_path = os.path.join(input_directory, path)
            if name.startswith("activations"):
                if "activations" not in dataframes:
                    dataframes["activations"] = []
                df = pd.read_csv(full_path, low_memory=False)
                dataframes["activations"].append(df)
            else:
                dataframes[name] = pd.read_csv(full_path, low_memory=False)
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
    print("   - LOG: Normalizando dados para análise (convertendo para minúsculas)...")
    columns_to_normalize = {
        'segments': ['Id', 'IncludeCriteria', 'ExcludeCriteria'],
        'activations': ['marketSegmentId', 'activationTargetSubjectConfig.developerName', 'attributesConfig.attributes.entityName', 'contactPointsConfig.contactPoints.contactPointEntityName'],
        'dmos': ['name'],
        'ci_expression': ['expression.table'],
        'mappings': ['sourceEntityDeveloperName'],
        'streams': ['dataLakeObjectInfo.name']
    }
    for df_key, columns in columns_to_normalize.items():
        if df_key in dfs and not dfs[df_key].empty:
            for col in columns:
                if col in dfs[df_key].columns:
                    dfs[df_key][col] = dfs[df_key][col].astype(str).str.lower()
    return dfs

# --- 3. Lógica de Análise (Com Otimizações) ---

# <--- OTIMIZAÇÃO: Lógica de análise de segmentos reescrita para ser mais performática --->
def analyze_segments(segments_df, activations_df, user_map):
    if segments_df.empty: return []
    print("Analisando Segmentos...")
    results = []
    
    segments_with_activations = set(activations_df['marketSegmentId'].unique()) if not activations_df.empty else set()
    
    # Combina os critérios para busca
    all_criteria = segments_df['IncludeCriteria'].fillna('') + segments_df['ExcludeCriteria'].fillna('')
    
    # Função auxiliar para verificar se o ID do segmento é usado como filtro em OUTROS segmentos
    def is_used_as_filter(segment_id, current_index):
        # Seleciona todos os critérios, exceto o da linha atual
        other_criteria = all_criteria.drop(current_index)
        # .str.contains é uma operação vetorizada e muito mais rápida
        return other_criteria.str.contains(segment_id, na=False).any()

    segments_df['LastPublishedEndDateTime_dt'] = pd.to_datetime(segments_df['LastPublishedEndDateTime'], errors='coerce')
    
    for index, row in segments_df.iterrows():
        status, reason = None, None
        is_older_than_30_days = pd.isna(row['LastPublishedEndDateTime_dt']) or (TODAY - row['LastPublishedEndDateTime_dt']) > timedelta(days=30)
        if not is_older_than_30_days: continue

        segment_id_lower = row['Id'] 
        
        # A verificação de filtro agora é mais eficiente
        used_as_filter = is_used_as_filter(segment_id_lower, index)
        has_activation = segment_id_lower in segments_with_activations
        
        if not used_as_filter:
            if has_activation:
                status, reason = "INATIVO", "Última publicação > 30 dias e não usado como filtro, mas possui ativação relacionada."
            else:
                status, reason = "ORFAO", "Última publicação > 30 dias, não usado como filtro e não possui ativação relacionada."
        elif used_as_filter and is_older_than_30_days:
             status, reason = "INATIVO", "Última publicação > 30 dias, mas é usado como filtro em outro segmento."
        
        if status:
            results.append({"DELETAR": "NAO", "ID_OR_API_NAME": row['Id'], "OBJECT_TYPE": "SEGMENT", "DELETION_IDENTIFIER": row['Id'], "DISPLAY_NAME": row['Name'], "STATUS": status, "Reason": reason, "CREATED_BY_NAME": user_map.get(row['CreatedById'], row['CreatedById'])})
    return results


def analyze_activations(activations_df, segments_to_delete_ids):
    if activations_df.empty or not segments_to_delete_ids: return []
    print("Analisando Ativações...")
    relevant_activations = activations_df[activations_df['marketSegmentId'].isin(segments_to_delete_ids)].copy()
    if relevant_activations.empty: return []
    
    grouped = relevant_activations.groupby(['id', 'name'])['marketSegmentId'].apply(list).reset_index()
    results = []
    for _, row in grouped.iterrows():
        reason_text = f"ativação associada a segmento marcado para exclusão: {tuple(row['marketSegmentId'])}"
        results.append({"DELETAR": "NAO", "ID_OR_API_NAME": row['id'], "OBJECT_TYPE": "ACTIVATION", "DELETION_IDENTIFIER": row['id'], "DISPLAY_NAME": row['name'], "STATUS": "ORFAO", "Reason": reason_text, "CREATED_BY_NAME": "N/A"})
    return results

# <--- OTIMIZAÇÃO: A função agora recebe 'all_segment_criteria_text' pré-calculado --->
def analyze_dmos(dmos_df, dmo_details_df, activations_df, ci_expression_df, user_map, all_segment_criteria_text):
    if dmos_df.empty: return []
    print("Analisando DMOs...")
    
    if not dmo_details_df.empty:
        dmo_details_df = dmo_details_df.rename(columns={'Id': 'id'})
        dmos_df = pd.merge(dmos_df, dmo_details_df[['id', 'CreatedDate', 'CreatedById']], on='id', how='left')
    else:
        dmos_df['CreatedDate'] = pd.NaT
        dmos_df['CreatedById'] = None

    results = []
    
    dmos_used_in_ci = set(ci_expression_df['expression.table'].unique()) if not ci_expression_df.empty else set()
    
    dmos_used_in_activations = set()
    if not activations_df.empty:
        dmos_used_in_activations.update(activations_df['activationTargetSubjectConfig.developerName'].dropna())
        dmos_used_in_activations.update(activations_df['attributesConfig.attributes.entityName'].dropna())
        dmos_used_in_activations.update(activations_df['contactPointsConfig.contactPoints.contactPointEntityName'].dropna())

    dmos_df['CreatedDate_dt'] = pd.to_datetime(dmos_df['CreatedDate'], errors='coerce')
        
    for _, row in dmos_df.iterrows():
        dmo_name_lower = row['name']
        if dmo_name_lower.startswith(DMO_PREFIXES_TO_EXCLUDE): continue
        if not pd.isna(row['CreatedDate_dt']) and (TODAY - row['CreatedDate_dt']) < timedelta(days=90): continue
            
        if not dmo_name_lower.endswith('__dlm'): continue
        if dmo_name_lower in dmos_used_in_ci: continue
        if dmo_name_lower in dmos_used_in_activations: continue
        
        # <--- OTIMIZAÇÃO: Substitui o loop 'any' por uma busca rápida em uma string única --->
        if dmo_name_lower in all_segment_criteria_text: continue
        
        reason = "É customizado (__dlm), não usado em Segmentos, Ativações ou CIs"
        reason += " e criado há mais de 90 dias." if 'CreatedDate' in dmos_df.columns and not pd.isna(row['CreatedDate_dt']) else "."
        
        created_by_name = user_map.get(row['CreatedById'], "N/A")
        results.append({"DELETAR": "NAO", "ID_OR_API_NAME": row['name'], "OBJECT_TYPE": "DMO", "DELETION_IDENTIFIER": row['name'], "DISPLAY_NAME": row['label'], "STATUS": "ORFAO", "Reason": reason, "CREATED_BY_NAME": created_by_name})
    return results


def analyze_data_streams(streams_df, stream_details_df, mappings_df, user_map):
    if streams_df.empty: return []
    print("Analisando Data Streams...")
    
    if not stream_details_df.empty:
        streams_with_details = pd.merge(streams_df, stream_details_df, on='Id', how='left', suffixes=('', '_details'))
    else:
        streams_with_details = streams_df.copy()
        streams_with_details['CreatedDate'] = pd.NaT
        streams_with_details['CreatedById'] = None
        
    streams_with_details['Effective_CreationDate'] = pd.to_datetime(streams_with_details['CreatedDate'], errors='coerce')
    streams_with_details['LastRefreshDate_dt'] = pd.to_datetime(streams_with_details.get('LastRefreshDate'), errors='coerce')
    dlos_with_mappings = set(mappings_df['sourceEntityDeveloperName'].unique()) if not mappings_df.empty else set()
    
    results = []
    for _, row in streams_with_details.iterrows():
        status, reason = None, None
        if not pd.isna(row['Effective_CreationDate']) and (TODAY - row['Effective_CreationDate']) < timedelta(days=90): continue
        
        is_older_than_30_days = pd.isna(row['LastRefreshDate_dt']) or (TODAY - row['LastRefreshDate_dt']) > timedelta(days=30)
        if not is_older_than_30_days: continue
        
        dlo_name_lower = row['dataLakeObjectInfo.name']
        has_mapping = dlo_name_lower in dlos_with_mappings
        
        if has_mapping:
            status, reason = "INATIVO", "Última atualização (LastRefreshDate) > 30 dias, mas possui mapeamento."
        else:
            status, reason = "ORFAO", "Última atualização (LastRefreshDate) > 30 dias e não possui mapeamento."
        
        if status:
            created_by_name = user_map.get(row['CreatedById'], "N/A")
            display_name = row['Name_details'] if 'Name_details' in row else row.get('Name', 'N/A')
            results.append({"DELETAR": "NAO", "ID_OR_API_NAME": row['dataLakeObjectInfo.name'], "OBJECT_TYPE": "DATA_STREAM", "DELETION_IDENTIFIER": row['dataLakeObjectInfo.name'], "DISPLAY_NAME": display_name, "STATUS": status, "Reason": reason, "CREATED_BY_NAME": created_by_name})
    return results

def analyze_calculated_insights(ci_df, user_map):
    if ci_df.empty: return []
    print("Analisando Calculated Insights...")
    results = []
    ci_df['lastRunDateTime_dt'] = pd.to_datetime(ci_df['lastRunDateTime'], errors='coerce')
    for _, row in ci_df.iterrows():
        is_successful = row['lastRunStatus'] == 'SUCCESS'
        is_older_than_90_days = pd.isna(row['lastRunDateTime_dt']) or (TODAY - row['lastRunDateTime_dt']) > timedelta(days=90)
        if is_successful and is_older_than_90_days:
            created_by_name = user_map.get(row['CreatedById'], "N/A")
            results.append({"DELETAR": "NAO", "ID_OR_API_NAME": row['apiName'], "OBJECT_TYPE": "CALCULATED_INSIGHTS", "DELETION_IDENTIFIER": row['apiName'], "DISPLAY_NAME": row['displayName'], "STATUS": "INATIVO", "Reason": "Último processamento bem-sucedido > 90 dias.", "CREATED_BY_NAME": created_by_name})
    return results

# --- 4. Orquestração Principal ---

def main():
    if not authenticate_jwt(SF_LOGIN_URL, SF_CLIENT_ID, SF_USERNAME, SF_PRIVATE_KEY_FILE):
        return
    
    files_to_load = {
        "segments": "MarketSegment.csv", 
        "activations": "ActivationDetails.csv",
        "dmos": "DataModelObjects.csv",
        "dmo_details": "DataModelObjectsDetails.csv", 
        "streams": "DataStreams.csv",
        "stream_details": "DataStreamDetails.csv",
        "dlos": "DataLakeObjects.csv", 
        "cis": "CalculatedInsights.csv", 
        "ci_expression": "CIExpression.csv", 
        "mappings": "mappings.csv", 
        "users": "Users.csv"
    }
    
    dfs = load_data_from_csv(files_to_load)
    if not dfs: return

    dfs = normalize_dataframes(dfs)

    user_map = {row['Id']: row['Name'] for _, row in dfs.get("users", pd.DataFrame()).iterrows()} if "users" in dfs and not dfs["users"].empty else {}
    print("🏁 Iniciando fase de análise dos dados...")
    
    activations_df = dfs.get("activations", pd.DataFrame())
    segments_df = dfs.get("segments", pd.DataFrame())
    
    segment_results = analyze_segments(segments_df, activations_df, user_map)
    segments_to_delete_ids = {str(res['ID_OR_API_NAME']).lower() for res in segment_results}
    
    activation_results = analyze_activations(activations_df, segments_to_delete_ids)
    
    # <--- OTIMIZAÇÃO: Pré-calcula a "string gigante" de critérios dos segmentos --->
    if not segments_df.empty:
        all_segment_criteria_text = ' '.join(segments_df['IncludeCriteria'].fillna('') + segments_df['ExcludeCriteria'].fillna(''))
    else:
        all_segment_criteria_text = ''
        
    dmo_results = analyze_dmos(dfs.get("dmos", pd.DataFrame()), dfs.get("dmo_details", pd.DataFrame()), activations_df, dfs.get("ci_expression", pd.DataFrame()), user_map, all_segment_criteria_text)
    
    stream_results = analyze_data_streams(dfs.get("streams", pd.DataFrame()), dfs.get("stream_details", pd.DataFrame()), dfs.get("mappings", pd.DataFrame()), user_map)
    ci_results = analyze_calculated_insights(dfs.get("cis", pd.DataFrame()), user_map)
    
    final_results = segment_results + activation_results + dmo_results + stream_results + ci_results
    if not final_results:
        print("\nAnálise concluída. Nenhum objeto atendeu aos critérios para deleção.")
        return
        
    final_df = pd.DataFrame(final_results)
    final_df.drop_duplicates(subset=['ID_OR_API_NAME', 'OBJECT_TYPE'], inplace=True, keep='first')
    
    output_filename = 'relatorio_delecao_final.csv'
    final_df = final_df[["DELETAR", "ID_OR_API_NAME", "OBJECT_TYPE", "DELETION_IDENTIFIER", "DISPLAY_NAME", "STATUS", "Reason", "CREATED_BY_NAME"]]
    final_df.to_csv(output_filename, index=False)
    
    print("\n" + "="*50)
    print(f"🎉 Análise concluída! O relatório foi salvo como '{output_filename}'")
    print(f"   Total de objetos identificados (após remoção de duplicatas): {len(final_df)}")
    print("="*50)

if __name__ == "__main__":
    main()