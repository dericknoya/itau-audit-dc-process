import pandas as pd
from datetime import datetime, timedelta, timezone
import os
import requests
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import time
from dotenv import load_dotenv
from tqdm import tqdm

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
DMO_PREFIXES_TO_EXCLUDE = ('ssot', 'unified', 'individual','Individual', 'einstein', 'segment_membership', 'AA_', 'aa_', 'aal_', 'AAL_', 'ibb_', 'iub_')

def get_timestamp():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def authenticate_jwt(login_url, client_id, username, private_key_file):
    print(f"{get_timestamp()} 🔐  Iniciando verificação de autenticação via JWT...")
    try:
        with open(private_key_file, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
        payload = {"iss": client_id, "sub": username, "aud": login_url, "exp": int(time.time()) + 180}
        token = jwt.encode(payload, private_key, algorithm="RS256")
        data = {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": token}
        auth_url = f"{login_url}/services/oauth2/token"
        response = requests.post(auth_url, data=data, proxies=proxies, verify=VERIFY_SSL)
        response.raise_for_status()
        print(f"{get_timestamp()} ✅  Autenticação bem-sucedida. Prosseguindo com a análise dos arquivos locais.")
        return True
    except FileNotFoundError:
        print(f"{get_timestamp()} ❌ ERRO DE AUTENTICAÇÃO: Arquivo de chave privada não encontrado em '{private_key_file}'")
    except Exception as e:
        print(f"{get_timestamp()} ❌ ERRO DE AUTENTICAÇÃO: {e}")
    print(f"{get_timestamp()} 🚫  A análise não pode continuar devido à falha na autenticação.")
    return False

# --- 2. Carregamento de Dados ---
def load_data_from_csv(files_to_load):
    print(f"\n{get_timestamp()} 📂 Carregando arquivos CSV do diretório 'dataExtract' para análise...")
    dataframes = {}
    input_directory = "dataExtract"
    for name, path in files_to_load.items():
        try:
            full_path = os.path.join(input_directory, path)
            # Lê todos os IDs como string para garantir a consistência na comparação
            df = pd.read_csv(full_path, low_memory=False, dtype=str)
            
            if name.startswith("activations"):
                if "activations" not in dataframes:
                    dataframes["activations"] = []
                dataframes["activations"].append(df)
            else:
                dataframes[name] = df
        except FileNotFoundError:
            print(f"{get_timestamp()}    - ⚠️  AVISO: Arquivo '{path}' não encontrado no diretório '{input_directory}'. Será ignorado.")
            dataframes[name] = pd.DataFrame()

    if "activations" in dataframes and isinstance(dataframes["activations"], list):
        if dataframes["activations"]:
            dataframes["activations"] = pd.concat(dataframes["activations"], ignore_index=True)
            print(f"{get_timestamp()}    - LOG: Arquivos de ativação unificados totalizando {len(dataframes['activations'])} linhas.")
        else:
            dataframes["activations"] = pd.DataFrame()
            
    print(f"{get_timestamp()} ✅  Carregamento de arquivos concluído!\n")
    return dataframes

# --- 3. Lógica de Análise ---

def analyze_segments(segments_df, activations_df, user_map):
    if segments_df.empty: return []
    
    results = []
    
    if 'marketsegmentid' in activations_df.columns and not activations_df.empty:
        # Para a verificação de ativações, usamos o ID completo de 18 caracteres
        segments_with_activations_full_id = set(activations_df['marketsegmentid'].dropna().astype(str).str.strip().str.lower())
    else:
        segments_with_activations_full_id = set()
    
    # Concatena todos os critérios. A busca aqui será feita com o ID de 15 caracteres.
    all_criteria_text = ' '.join(segments_df['includecriteria'].fillna('') + segments_df['excludecriteria'].fillna('')).lower()
    
    segments_df['lastpublishstatusdatetime_dt'] = pd.to_datetime(segments_df['lastpublishstatusdatetime'], errors='coerce')
    
    for _, row in tqdm(segments_df.iterrows(), total=segments_df.shape[0], desc=f"{get_timestamp()} Analisando Segmentos"):
        status, reason = None, None
        is_older_than_30_days = pd.isna(row['lastpublishstatusdatetime_dt']) or (TODAY - row['lastpublishstatusdatetime_dt']) > timedelta(days=30)
        if not is_older_than_30_days: continue

        # --- LÓGICA CORRIGIDA FINAL ---
        # Pega o ID completo (18 caracteres) para checar ativações
        full_segment_id = str(row['id']).strip().lower()
        # Pega o ID truncado (15 caracteres) para checar se é usado como filtro
        truncated_segment_id = full_segment_id[:15]

        # A contagem agora é feita com o ID de 15 caracteres.
        # Se a contagem for > 1, ele é usado como filtro em outro segmento.
        used_as_filter = all_criteria_text.count(truncated_segment_id) > 1
        
        # A verificação de ativação continua com o ID completo.
        has_activation = full_segment_id in segments_with_activations_full_id
        
        # Lógica para determinar o status do segmento
        if not used_as_filter:
            if has_activation:
                status, reason = "INATIVO", "Última publicação > 30 dias e não usado como filtro, mas possui ativação relacionada."
            else:
                status, reason = "ORFAO", "Última publicação > 30 dias, não usado como filtro e não possui ativação relacionada."
        elif used_as_filter and is_older_than_30_days:
             # Este status é para segmentos que SÃO usados como filtro, mas estão inativos.
             # Pela regra, eles não devem ser listados para exclusão, então não adicionamos à lista.
             # Se você quisesse listá-los como 'INATIVO', a linha de 'append' viria aqui.
             pass # Intencionalmente não faz nada, pois não deve ser excluído.
        
        if status:
            results.append({"DELETAR": "NAO", "ID_OR_API_NAME": row['id'], "OBJECT_TYPE": "SEGMENT","LAST_REFRESH_DATE": row['lastpublishstatusdatetime_dt'], "DELETION_IDENTIFIER": row['id'], "DISPLAY_NAME": row['name'], "STATUS": status, "Reason": reason, "CREATED_BY_NAME": user_map.get(row['createdbyid'], row['createdbyid'])})
            
    print(f"{get_timestamp()} Análise de Segmentos concluída.")
    return results

def analyze_activations(activations_df, segments_to_delete_ids):
    if activations_df.empty or not segments_to_delete_ids: return []
    
    relevant_activations = activations_df[activations_df['marketsegmentid'].isin(segments_to_delete_ids)].copy()
    if relevant_activations.empty: return []
    
    grouped = relevant_activations.groupby(['id', 'name'])['marketsegmentid'].apply(list).reset_index()
    results = []
    for _, row in tqdm(grouped.iterrows(), total=grouped.shape[0], desc=f"{get_timestamp()} Analisando Ativações Órfãs"):
        reason_text = f"ativação associada a segmento marcado para exclusão: {tuple(row['marketsegmentid'])}"
        results.append({"DELETAR": "NAO", "ID_OR_API_NAME": row['id'], "LAST_REFRESH_DATE": "", "OBJECT_TYPE": "ACTIVATION", "DELETION_IDENTIFIER": row['id'], "DISPLAY_NAME": row['name'], "STATUS": "ORFAO", "Reason": reason_text, "CREATED_BY_NAME": "N/A"})
    print(f"{get_timestamp()} Análise de Ativações Órfãs concluída.")
    return results

def analyze_dmos(dmos_df, dmo_details_df, activations_df, ci_expression_df, user_map, all_segment_criteria_text):
    if dmos_df.empty: return []
    
    if not dmo_details_df.empty:
        dmos_df = pd.merge(dmos_df, dmo_details_df[['id', 'createddate', 'createdbyid']], on='id', how='left')
    else:
        dmos_df['createddate'] = pd.NaT
        dmos_df['createdbyid'] = None

    results = []
    dmos_used_in_ci = set(ci_expression_df['expression.table'].unique()) if 'expression.table' in ci_expression_df.columns and not ci_expression_df.empty else set()
    
    dmos_used_in_activations = set()
    if not activations_df.empty:
        if 'activationtargetsubjectconfig.developername' in activations_df.columns:
            dmos_used_in_activations.update(activations_df['activationtargetsubjectconfig.developername'].dropna())
        if 'attributesconfig.attributes.entityname' in activations_df.columns:
            dmos_used_in_activations.update(activations_df['attributesconfig.attributes.entityname'].dropna())
        if 'contactpointsconfig.contactpoints.contactpointentityname' in activations_df.columns:
            dmos_used_in_activations.update(activations_df['contactpointsconfig.contactpoints.contactpointentityname'].dropna())

    dmos_df['createddate_dt'] = pd.to_datetime(dmos_df.get('createddate'), errors='coerce')
        
    for _, row in tqdm(dmos_df.iterrows(), total=dmos_df.shape[0], desc=f"{get_timestamp()} Analisando DMOs"):
        dmo_name = row['name']
        if any(dmo_name.startswith(p) for p in DMO_PREFIXES_TO_EXCLUDE): continue
        if not pd.isna(row['createddate_dt']) and (TODAY - row['createddate_dt']) < timedelta(days=90): continue
        if not dmo_name.endswith('__dlm'): continue
        if dmo_name in dmos_used_in_ci: continue
        if dmo_name in dmos_used_in_activations: continue
        if dmo_name in all_segment_criteria_text: continue
        
        reason = "Não usado em Segmentos, Ativações ou CIs"
        reason += " e criado há mais de 90 dias." if 'createddate_dt' in dmos_df.columns and not pd.isna(row['createddate_dt']) else "."
        
        created_by_name = user_map.get(row.get('createdbyid'), "N/A")
        results.append({"DELETAR": "NAO", "ID_OR_API_NAME": row['name'], "LAST_REFRESH_DATE": "", "OBJECT_TYPE": "DMO", "DELETION_IDENTIFIER": row['name'], "DISPLAY_NAME": row['label'], "STATUS": "ORFAO", "Reason": reason, "CREATED_BY_NAME": created_by_name})
    print(f"{get_timestamp()} Análise de DMOs concluída.")
    return results

def analyze_data_streams(streams_df, stream_details_df, mappings_df, user_map):
    if streams_df.empty: return []
    
    streams_unique_df = streams_df.drop_duplicates(subset=['recordid']).copy()
    
    if not stream_details_df.empty:
        streams_with_details = pd.merge(streams_unique_df, stream_details_df, left_on='recordid', right_on='id', how='left', suffixes=('', '_details'))
    else:
        streams_with_details = streams_unique_df.copy()
        streams_with_details['createddate'] = pd.NaT
        streams_with_details['createdbyid'] = None
        
    streams_with_details['effective_creationdate'] = pd.to_datetime(streams_with_details.get('createddate'), errors='coerce')
    streams_with_details['lastrefreshdate_dt'] = pd.to_datetime(streams_with_details.get('lastrefreshdate'), errors='coerce')
    dlos_with_mappings = set(mappings_df['sourceentitydevelopername'].unique()) if 'sourceentitydevelopername' in mappings_df.columns and not mappings_df.empty else set()
    
    results = []
    for _, row in tqdm(streams_with_details.iterrows(), total=streams_with_details.shape[0], desc=f"{get_timestamp()} Analisando Data Streams"):
        status, reason = None, None
        if not pd.isna(row['effective_creationdate']) and (TODAY - row['effective_creationdate']) < timedelta(days=90): continue
        
        is_older_than_30_days = pd.isna(row['lastrefreshdate_dt']) or (TODAY - row['lastrefreshdate_dt']) > timedelta(days=30)
        if not is_older_than_30_days: continue
        
        dlo_name = row['datalakeobjectinfo.name']
        has_mapping = dlo_name in dlos_with_mappings
        
        if has_mapping:
            status, reason = "INATIVO", "Última atualização (LastRefreshDate) > 30 dias, mas possui mapeamento."
        else:
            status, reason = "ORFAO", "Última atualização (LastRefreshDate) > 30 dias e não possui mapeamento."
        
        if status:
            created_by_name = user_map.get(row.get('createdbyid'), "N/A")
            display_name = row['name_details'] if 'name_details' in row and pd.notna(row['name_details']) else row.get('name', 'N/A')
            results.append({"DELETAR": "NAO", "ID_OR_API_NAME": row['datalakeobjectinfo.name'], "LAST_REFRESH_DATE": row['lastrefreshdate_dt'], "OBJECT_TYPE": "DATA_STREAM", "DELETION_IDENTIFIER": row['datalakeobjectinfo.name'], "DISPLAY_NAME": display_name, "STATUS": status, "Reason": reason, "CREATED_BY_NAME": created_by_name})
    print(f"{get_timestamp()} Análise de Data Streams concluída.")
    return results

def analyze_calculated_insights(ci_df, user_map):
    if ci_df.empty: return []

    results = []
    ci_df['lastrundatetime_dt'] = pd.to_datetime(ci_df['lastrundatetime'], errors='coerce')
    for _, row in tqdm(ci_df.iterrows(), total=ci_df.shape[0], desc=f"{get_timestamp()} Analisando Calculated Insights"):
        is_successful = row['lastrunstatus'] == 'SUCCESS'
        is_older_than_90_days = pd.isna(row['lastrundatetime_dt']) or (TODAY - row['lastrundatetime_dt']) > timedelta(days=90)
        if is_successful and is_older_than_90_days:
            created_by_name = user_map.get(row.get('createdbyid'), "N/A")
            results.append({"DELETAR": "NAO", "ID_OR_API_NAME": row['apiname'], "LAST_REFRESH_DATE": row['lastrundatetime_dt'], "OBJECT_TYPE": "CALCULATED_INSIGHTS", "DELETION_IDENTIFIER": row['apiname'], "DISPLAY_NAME": row['displayname'], "STATUS": "INATIVO", "Reason": "Último processamento bem-sucedido > 90 dias.", "CREATED_BY_NAME": created_by_name})
    print(f"{get_timestamp()} Análise de Calculated Insights concluída.")
    return results

# --- 4. Orquestração Principal ---

def main():
    if not authenticate_jwt(SF_LOGIN_URL, SF_CLIENT_ID, SF_USERNAME, SF_PRIVATE_KEY_FILE):
        return
    
    files_to_load = { "segments": "MarketSegment.csv", 
                     "activations": "ActivationDetails.csv",
                    "dmos": "DataModelObjects.csv", 
                    "dmo_details": "DataModelObjectsDetails.csv", 
                    "streams": "DataStreams.csv", 
                    "stream_details": "DataStreamDetails.csv", 
                    "dlos": "DataLakeObjects.csv", 
                    "cis": "CalculatedInsights.csv", 
                    "ci_expression": "CIExpression.csv", 
                    "mappings": "mappings.csv", 
                    "users": "Users.csv" }
    
    dfs = load_data_from_csv(files_to_load)
    if not dfs: return

    user_map = {row['id']: row['name'] for _, row in dfs.get("users", pd.DataFrame()).iterrows()} if "users" in dfs and not dfs["users"].empty else {}
    print(f"{get_timestamp()} 🏁 Iniciando fase de análise dos dados...")
    
    activations_df = dfs.get("activations", pd.DataFrame())
    segments_df = dfs.get("segments", pd.DataFrame())
    
    segment_results = analyze_segments(segments_df, activations_df, user_map)
    segments_to_delete_ids = {str(res['ID_OR_API_NAME']) for res in segment_results}
    
    activation_results = analyze_activations(activations_df, segments_to_delete_ids)
    
    if not segments_df.empty:
        all_segment_criteria_text = ' '.join(segments_df['includecriteria'].fillna('') + segments_df['excludecriteria'].fillna(''))
    else:
        all_segment_criteria_text = ''
        
    dmo_results = analyze_dmos(dfs.get("dmos", pd.DataFrame()), dfs.get("dmo_details", pd.DataFrame()), activations_df, dfs.get("ci_expression", pd.DataFrame()), user_map, all_segment_criteria_text)
    stream_results = analyze_data_streams(dfs.get("streams", pd.DataFrame()), dfs.get("stream_details", pd.DataFrame()), dfs.get("mappings", pd.DataFrame()), user_map)
    ci_results = analyze_calculated_insights(dfs.get("cis", pd.DataFrame()), user_map)
    
    final_results = segment_results + activation_results + dmo_results + stream_results + ci_results
    if not final_results:
        print(f"\n{get_timestamp()} Análise concluída. Nenhum objeto atendeu aos critérios para deleção.")
        return
        
    final_df = pd.DataFrame(final_results)
    final_df.drop_duplicates(subset=['ID_OR_API_NAME', 'OBJECT_TYPE'], inplace=True, keep='first')
    
    output_filename = 'audit_objetos_para_exclusao.csv'
    final_df = final_df[["DELETAR", "ID_OR_API_NAME","LAST_REFRESH_DATE", "OBJECT_TYPE", "DELETION_IDENTIFIER", "DISPLAY_NAME", "STATUS", "Reason", "CREATED_BY_NAME"]]
    final_df.to_csv(output_filename, index=False)
    
    print("\n" + "="*50)
    print(f"{get_timestamp()} 🎉 Análise concluída! O relatório foi salvo como '{output_filename}'")
    print(f"{get_timestamp()}    Total de objetos identificados (após remoção de duplicatas): {len(final_df)}")
    print("="*50)

if __name__ == "__main__":
    main()