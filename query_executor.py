import requests
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import time
import json
import gzip
import csv
from urllib.parse import quote_plus, urlparse, parse_qs, urlencode, urlunparse
import os
import re
from itertools import product
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple, Generator
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# --- Configuration ---
# Carrega as variáveis de ambiente do arquivo .env
load_dotenv()

# As credenciais agora são lidas do arquivo .env
SF_LOGIN_URL = os.getenv("SF_LOGIN_URL")
SF_API_VERSION = "v64.0"
SF_CLIENT_ID = os.getenv("SF_CLIENT_ID")
SF_USERNAME = os.getenv("SF_USERNAME")
SF_PRIVATE_KEY_FILE = os.getenv("SF_PRIVATE_KEY_FILE", "private.pem")

USE_PROXY = os.getenv("USE_PROXY", "False").lower() == "true"
PROXY_URL = os.getenv("PROXY_URL")
VERIFY_SSL = os.getenv("VERIFY_SSL", "True").lower() == "true"

# Configuration for query file and output file naming
QUERY_CONFIG_FILE = "QueryConfig.csv"
OUTPUT_DIRECTORY = "dataExtract"
RATE_LIMIT_PAUSE_MINUTES = 10
BULK_JOB_POLL_INTERVAL_SECONDS = 10
MAX_WORKERS = 10

proxies = {'http': PROXY_URL, 'https': PROXY_URL} if USE_PROXY else None

# Suprime os avisos de requisição HTTPS não verificada se VERIFY_SSL for False
if not VERIFY_SSL:
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# --- Resilient Authentication and API Requests ---

class SalesforceAuthenticator:
    """
    Gerencia o ciclo de vida do token de acesso JWT do Salesforce.
    """
    def __init__(self, login_url: str, client_id: str, username: str, private_key_file: str):
        self.login_url = login_url
        self.client_id = client_id
        self.username = username
        self.private_key_file = private_key_file
        self.access_token: Optional[str] = None
        self.instance_url: Optional[str] = None

    def _authenticate(self) -> bool:
        """
        Lógica de autenticação interna para obter um novo token.
        """
        try:
            with open(self.private_key_file, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(), password=None, backend=default_backend()
                )
            payload = {
                "iss": self.client_id, "sub": self.username, "aud": self.login_url,
                "exp": int(time.time()) + 3600 # 1 hora de validade
            }
            token = jwt.encode(payload, private_key, algorithm="RS256")
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            data = {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": token}
            auth_url = f"{self.login_url}/services/oauth2/token"
            
            response = requests.post(auth_url, headers=headers, data=data, proxies=proxies, verify=VERIFY_SSL)
            response.raise_for_status()
            
            auth_data = response.json()
            self.access_token = auth_data["access_token"]
            self.instance_url = auth_data["instance_url"]
            print("✅ JWT authentication successful.")
            return True
        except FileNotFoundError:
            print(f"❌ Authentication error: Private key file not found at '{self.private_key_file}'")
        except Exception as e:
            print(f"❌ Error during JWT authentication: {e}")
        return False

    def get_credentials(self) -> Optional[Tuple[str, str]]:
        if not self.access_token or not self.instance_url:
            if not self._authenticate():
                return None
        return self.access_token, self.instance_url

    def refresh_credentials(self) -> Optional[Tuple[str, str]]:
        tqdm.write("🔄 Refreshing expired access token...")
        if self._authenticate():
            return self.access_token, self.instance_url
        return None

def make_resilient_request(
    authenticator: SalesforceAuthenticator,
    method: str,
    url: str,
    **kwargs: Any
) -> requests.Response:
    """
    Wrapper para chamadas `requests` que lida com a expiração do token (401).
    """
    credentials = authenticator.get_credentials()
    if not credentials:
        raise ConnectionError("Failed to get initial authentication credentials.")
    
    access_token, _ = credentials
    
    if 'headers' not in kwargs:
        kwargs['headers'] = {}
    kwargs['headers']['Authorization'] = f"Bearer {access_token}"
    
    kwargs['proxies'] = proxies
    kwargs['verify'] = VERIFY_SSL

    response = requests.request(method, url, **kwargs)
    
    if response.status_code == 401:
        tqdm.write("Token expired (401 Unauthorized). Retrying with a new token...")
        new_credentials = authenticator.refresh_credentials()
        if not new_credentials:
            raise ConnectionError("Failed to refresh authentication credentials.")
        
        new_access_token, _ = new_credentials
        kwargs['headers']['Authorization'] = f"Bearer {new_access_token}"
        
        response = requests.request(method, url, **kwargs)
    
    return response


# --- Utility Functions ---

def parse_select_clause_with_aliases(select_clause_str: str) -> Tuple[List[str], List[str]]:
    api_fields = []
    header_fields = []
    field_definitions = [p.strip() for p in select_clause_str.split(',')]
    
    for definition in field_definitions:
        parts = [p.strip() for p in re.split(r'\s+as\s+', definition, flags=re.IGNORECASE)]
        if len(parts) == 2:
            api_fields.append(parts[0])
            header_fields.append(parts[1])
        else:
            api_fields.append(parts[0])
            header_fields.append(parts[0])
            
    return api_fields, header_fields

def rename_record_keys(records: List[Dict], api_fields: List[str], header_fields: List[str]) -> List[Dict]:
    if not records or api_fields == header_fields:
        return records

    api_to_header_map = dict(zip(api_fields, header_fields))
    renamed_records = []
    for record in records:
        renamed_record = {api_to_header_map.get(key, key): value for key, value in record.items()}
        renamed_records.append(renamed_record)
    return renamed_records


# --- Bulk Query API Functions ---

def create_bulk_job(auth: SalesforceAuthenticator, api_version: str, soql_query: str) -> Optional[str]:
    print(f"🔄 Creating Bulk API job...")
    _, instance_url = auth.get_credentials()
    job_url = f"{instance_url}/services/data/{api_version}/jobs/query"
    headers = {"Content-Type": "application/json"}
    job_payload = {"operation": "query", "query": soql_query, "contentType": "CSV"}
    try:
        response = make_resilient_request(auth, 'post', job_url, headers=headers, data=json.dumps(job_payload))
        response.raise_for_status()
        job_id = response.json()["id"]
        print(f"✅ Job created with ID: {job_id}")
        return job_id
    except requests.exceptions.RequestException as e:
        print(f"❌ Error creating bulk job: {e}")
        return None

def wait_for_job_completion(auth: SalesforceAuthenticator, api_version: str, job_id: str, object_name: str) -> Tuple[str, int]:
    _, instance_url = auth.get_credentials()
    job_status_url = f"{instance_url}/services/data/{api_version}/jobs/query/{job_id}"
    records_processed = 0
    while True:
        try:
            response = make_resilient_request(auth, 'get', job_status_url)
            response.raise_for_status()
            job_status = response.json()
            state = job_status.get("state")
            records_processed = job_status.get("numberRecordsProcessed", 0)
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            print(f"⏳ {timestamp} | {object_name} | Job {job_id} | Status: {state} | Processed: {records_processed} records")
            
            if state in ["JobComplete", "Aborted", "Failed"]:
                if state in ["Failed", "Aborted"]:
                    print(f"❌ Job failed or aborted. Message: {job_status.get('errorMessage')}")
                return state, records_processed
                
            time.sleep(BULK_JOB_POLL_INTERVAL_SECONDS)
        except requests.exceptions.RequestException as e:
            print(f"❌ Error polling job status: {e}")
            return "Failed", 0

def download_bulk_results(auth: SalesforceAuthenticator, api_version: str, job_id: str, output_file: str, header_fields: Optional[List[str]] = None) -> bool:
    print(f"⬇️ Starting to download Bulk API results to {output_file}...")
    _, instance_url = auth.get_credentials()
    base_results_url = f"{instance_url}/services/data/{api_version}/jobs/query/{job_id}/results"
    
    is_first_request = True
    locator = None

    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as out_f:
            writer = csv.writer(out_f)
            
            while is_first_request or locator:
                request_url = f"{base_results_url}?locator={locator}" if locator else base_results_url
                
                response = make_resilient_request(auth, 'get', request_url, stream=True)
                response.raise_for_status()

                raw_content = response.content
                try:
                    decoded_content = gzip.decompress(raw_content).decode('utf-8')
                except gzip.BadGzipFile:
                    decoded_content = raw_content.decode('utf-8')
                
                lines = decoded_content.strip().splitlines()
                if not lines:
                    break

                reader = csv.reader(lines)
                
                if is_first_request:
                    original_header = next(reader)
                    writer.writerow(header_fields if header_fields else original_header)
                    is_first_request = False
                else:
                    next(reader)
                
                for row in reader:
                    sanitized_row = [' '.join(field.split()) for field in row]
                    writer.writerow(sanitized_row)
                
                locator = response.headers.get('Sforce-Locator')
                if locator and locator.lower() != 'null':
                     print(f"  ➡️  Found next batch with locator: {locator[:10]}...")
                else:
                    locator = None

        print(f"✅ All result batches downloaded and saved to {output_file}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"❌ Error downloading and writing results: {e}")
        return False
    except Exception as e:
        print(f"❌ An unexpected error occurred during bulk download: {e}")
        return False


# --- CSV Sanitization Helper ---

def sanitize_csv_rows(record_list: List[Dict]) -> List[Dict]:
    for row in record_list:
        for key, value in row.items():
            if isinstance(value, str):
                row[key] = ' '.join(value.split())
    return record_list


# --- Paginated Query (Standard & Tooling) API Functions ---

def flatten_record(record: Dict, parent_key: str = '', sep: str ='.') -> Dict:
    items = []
    for k, v in record.items():
        if k == 'attributes': continue
        new_key = parent_key + sep + k if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_record(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)

def process_paginated_query(auth: SalesforceAuthenticator, api_version: str, soql_query: str, output_file: str, api_fields: List[str], header_fields: List[str], query_endpoint_template: str) -> int:
    _, instance_url = auth.get_credentials()
    encoded_query = quote_plus(soql_query)
    query_endpoint = query_endpoint_template.format(api_version=api_version)
    next_records_url = f"/{query_endpoint}?q={encoded_query}"
    
    csv_writer, total_records_fetched, total_size = None, 0, 0
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            while next_records_url:
                try:
                    response = make_resilient_request(auth, 'get', f"{instance_url}{next_records_url}")
                    response.raise_for_status()
                    result = response.json()
                except requests.exceptions.RequestException as e:
                    print(f"⚠️ Request failed: {e}. Stopping pagination for this query.")
                    break

                if total_size == 0: total_size = result.get('size', 0)
                records = result.get('records', [])
                if not records and total_records_fetched == 0:
                    print("✅ Query returned no records.")
                    return 0
                elif not records:
                    break
                
                flattened_records = [flatten_record(rec) for rec in records]
                sanitized_records = sanitize_csv_rows(flattened_records)
                aliased_records = rename_record_keys(sanitized_records, api_fields, header_fields)

                if csv_writer is None and aliased_records:
                    csv_writer = csv.DictWriter(csvfile, fieldnames=header_fields)
                    csv_writer.writeheader()
                if csv_writer: csv_writer.writerows(aliased_records)
                
                total_records_fetched += len(records)
                print(f"⏳ Fetched {total_records_fetched} of {total_size} records...")
                next_records_url = result.get('nextRecordsUrl')
        
        if total_records_fetched > 0:
            print(f"✅ Successfully wrote {total_records_fetched} records to {output_file}")
        return total_records_fetched

    except Exception as e:
        print(f"❌ An error occurred during paginated query execution: {e}")
        return 0

def execute_standard_query(auth: SalesforceAuthenticator, api_version: str, soql_query: str, output_file: str) -> int:
    print(f"🔄 Executing 'Standard' query, writing to {output_file}...")
    select_clause = soql_query.split(' FROM ')[0][len('SELECT '):]
    from_clause = soql_query.split(' FROM ')[1]
    api_fields, header_fields = parse_select_clause_with_aliases(select_clause)
    api_soql = f"SELECT {', '.join(api_fields)} FROM {from_clause}"
    
    endpoint_template = "services/data/{api_version}/query"
    return process_paginated_query(auth, api_version, api_soql, output_file, api_fields, header_fields, endpoint_template)

def execute_tooling_query(auth: SalesforceAuthenticator, api_version: str, soql_query: str, output_file: str) -> int:
    print(f"🔄 Executing 'Tooling' query, writing to {output_file}...")
    select_clause = soql_query.split(' FROM ')[0][len('SELECT '):]
    from_clause = soql_query.split(' FROM ')[1]
    api_fields, header_fields = parse_select_clause_with_aliases(select_clause)
    api_soql = f"SELECT {', '.join(api_fields)} FROM {from_clause}"
    
    endpoint_template = "services/data/{api_version}/tooling/query"
    return process_paginated_query(auth, api_version, api_soql, output_file, api_fields, header_fields, endpoint_template)


# --- SSOT & LocalParse API Function Helpers ---

def get_nested_value(record: Dict, path: str) -> Any:
    value = record
    try:
        for key in path.split('.'):
            value = value.get(key)
            if value is None:
                return None
    except AttributeError:
        return None
    return value

def apply_client_side_filter(records: List[Dict], conditions: List[Dict]) -> List[Dict]:
    if not conditions:
        return records

    filtered_records = []
    for record in records:
        all_conditions_met = True
        for condition in conditions:
            field, op, value = condition['field'], condition['op'], condition['value']
            actual_value = get_nested_value(record, field)
            
            match = False
            if op == '=' and str(actual_value) == value:
                match = True
            elif op == '<>' and str(actual_value) != value:
                match = True
            
            if not match:
                all_conditions_met = False
                break
        
        if all_conditions_met:
            filtered_records.append(record)
    
    print(f"🔍 Filter applied: {len(records)} records -> {len(filtered_records)} records")
    return filtered_records

def expand_and_flatten_json(current_data: Any, fields_map: Dict[str, str]) -> List[Dict]:
    if not isinstance(current_data, dict):
        return [{full_path: None for full_path in fields_map}]

    groups = {}
    for full_path, remaining_path in fields_map.items():
        if not remaining_path: continue
        key = remaining_path.split('.')[0]
        if key not in groups: groups[key] = {}
        groups[key][full_path] = '.'.join(remaining_path.split('.')[1:])
    
    processed_groups = []
    for key, sub_fields_map in groups.items():
        if '*' in key:
            pattern = key.replace('*', '')
            group_rows = []
            matching_keys = [k for k in current_data.keys() if k.startswith(pattern)]
            if not matching_keys:
                group_rows = [{full_path: None for full_path in sub_fields_map}]
            else:
                for matching_key in matching_keys:
                    child_data = current_data.get(matching_key)
                    group_rows.extend(expand_and_flatten_json(child_data, sub_fields_map))
        else:
            child_data = current_data.get(key)
            is_leaf_group = all(not rem_path for rem_path in sub_fields_map.values())
            if is_leaf_group:
                if isinstance(child_data, list):
                    group_rows = [{full_path: item for full_path in sub_fields_map} for item in child_data]
                    if not group_rows: group_rows = [{full_path: None for full_path in sub_fields_map}]
                else:
                    group_rows = [{full_path: child_data for full_path in sub_fields_map}]
            else:
                if isinstance(child_data, list):
                    group_rows = []
                    for item in child_data:
                        group_rows.extend(expand_and_flatten_json(item, sub_fields_map))
                    if not group_rows: group_rows = [{full_path: None for full_path in sub_fields_map}]
                else:
                    group_rows = expand_and_flatten_json(child_data, sub_fields_map)
        
        processed_groups.append(group_rows)
        
    final_rows = []
    if not processed_groups: return [{}]
        
    for combination in product(*processed_groups):
        new_row = {}
        for partial_row in combination:
            new_row.update(partial_row)
        final_rows.append(new_row)
        
    return final_rows if final_rows else [{}]

def flatten_ssot_records(records: List[Dict], api_fields: List[str]) -> List[Dict]:
    all_final_rows = []
    if not records:
        return all_final_rows

    for record in records:
        base_row_data = {field: record.get(field) for field in api_fields if '.' not in field}
        nested_fields = [field for field in api_fields if '.' in field]
        
        if nested_fields:
            initial_map = {field: field for field in nested_fields}
            expanded_rows = expand_and_flatten_json(record, initial_map)
            for expanded_row in expanded_rows:
                combined_row = base_row_data.copy()
                combined_row.update(expanded_row)
                all_final_rows.append(combined_row)
        else:
            all_final_rows.append(base_row_data)
            
    return all_final_rows

def find_data_in_response(data: Dict, paths: List[str]) -> Optional[Any]:
    for path in paths:
        value = data
        try:
            for key in path.split('.'): value = value[key]
            return value
        except (KeyError, TypeError, IndexError): continue
    return None

def stream_all_ssot_pages(auth: SalesforceAuthenticator, start_url: str, entry_point: str, object_name_for_key: str, api_fields: List[str], filter_conditions: Optional[List[Dict]]) -> Generator[List[Dict], None, None]:
    _, instance_url = auth.get_credentials()
    parsed_initial_url = urlparse(start_url)
    initial_params = parse_qs(parsed_initial_url.query)
    is_offset_mode = 'offset' in initial_params

    if is_offset_mode:
        current_offset = int(initial_params.get('offset', ['0'])[0])
        while True:
            url_parts = list(parsed_initial_url); query_params = parse_qs(url_parts[4])
            query_params['offset'] = [str(current_offset)]; url_parts[4] = urlencode(query_params, doseq=True)
            next_request_url = urlunparse(url_parts)
            try:
                response = make_resilient_request(auth, 'get', next_request_url)
                response.raise_for_status(); result_data = response.json()
            except requests.exceptions.RequestException as e:
                tqdm.write(f"⚠️ Request failed: {e}. Stopping pagination for this request.")
                return

            records = find_data_in_response(result_data, [entry_point]) if entry_point else (find_data_in_response(result_data, [object_name_for_key.lower()]) or result_data)
            if not isinstance(records, list):
                if isinstance(result_data, dict): records = [result_data]
                else: records = []
            
            if not records: break
            if filter_conditions: records = apply_client_side_filter(records, filter_conditions)
            page_rows = flatten_ssot_records(records, api_fields)
            yield page_rows
            current_offset += len(records)
    else:
        next_request_url = start_url
        while next_request_url:
            retry_count = 0
            max_retries = 5
            response = None
            while retry_count < max_retries:
                try:
                    response = make_resilient_request(auth, 'get', next_request_url)
                    response.raise_for_status()
                    result_data = response.json()
                    break
                except requests.exceptions.HTTPError as e:
                    if e.response.status_code >= 500 and retry_count < max_retries -1:
                        retry_count += 1
                        error_content = e.response.text
                        tqdm.write(f"⚠️ Server error ({e.response.status_code}) - {error_content}. Pausing for {RATE_LIMIT_PAUSE_MINUTES} minutes. Retry {retry_count}/{max_retries-1}...")
                        time.sleep(RATE_LIMIT_PAUSE_MINUTES * 60)
                    else:
                        tqdm.write(f"❌ HTTP Error: {e}. Stopping pagination.")
                        return
                except requests.exceptions.RequestException as e:
                    tqdm.write(f"⚠️ Request failed: {e}. Stopping pagination.")
                    return
            
            if not response or not response.ok:
                tqdm.write(f"❌ Max retries reached for {next_request_url}. Skipping.")
                return

            records = find_data_in_response(result_data, [entry_point]) if entry_point else (find_data_in_response(result_data, [object_name_for_key.lower()]) or result_data)
            if not isinstance(records, list):
                 if isinstance(result_data, dict): records = [result_data]
                 else: records = []

            if filter_conditions: records = apply_client_side_filter(records, filter_conditions)
            next_page_relative_url = find_data_in_response(result_data, ['nextPageUrl', 'collection.nextPageUrl'])
            
            if not records and not next_page_relative_url: break
            
            page_rows = flatten_ssot_records(records, api_fields)
            yield page_rows
            
            if next_page_relative_url:
                parsed_url = urlparse(next_page_relative_url)
                query_params = parse_qs(parsed_url.query)
                if 'pageToken' in query_params: del query_params['pageToken']
                new_query_string = urlencode(query_params, doseq=True)
                url_parts = list(parsed_url); url_parts[4] = new_query_string
                clean_relative_url = urlunparse(url_parts)
                next_request_url = f"{instance_url}{clean_relative_url}"
            else:
                next_request_url = None

def fetch_ssot_for_row(
    auth: SalesforceAuthenticator, 
    api_version: str, 
    base_object_url: str, 
    source_row: Dict, 
    params: Dict,
    param_names_for_request: List[str],
    source_param_columns: List[str],
    entry_point: str,
    object_name_for_key: str,
    api_fields: List[str],
    header_fields: List[str]
) -> Optional[List[Dict]]:
    try:
        _, instance_url = auth.get_credentials()
        iter_params = params.copy()
        base_url_for_iter = f"{instance_url}/services/data/{api_version}/ssot/{base_object_url}"

        if len(param_names_for_request) == 1 and param_names_for_request[0] == '/':
            value = source_row.get(source_param_columns[0], '')
            base_url_for_iter = f"{base_url_for_iter}/{value}"
        else:
            for param_name, source_col in zip(param_names_for_request, source_param_columns):
                value = source_row.get(source_col, '')
                iter_params[param_name] = [value]

        query_string_for_iter = urlencode(iter_params, doseq=True)
        start_url = f"{base_url_for_iter}?{query_string_for_iter}" if query_string_for_iter else base_url_for_iter
        
        all_rows_for_this_item = []
        page_generator = stream_all_ssot_pages(auth, start_url, entry_point, object_name_for_key, api_fields, None)
        
        for page_of_rows in page_generator:
            if page_of_rows:
                sanitized_rows = sanitize_csv_rows(page_of_rows)
                aliased_rows = rename_record_keys(sanitized_rows, api_fields, header_fields)
                all_rows_for_this_item.extend(aliased_rows)
        
        return all_rows_for_this_item
    except Exception as e:
        tqdm.write(f"❌ Error in worker for row {source_row}: {e}")
        return None

def execute_ssot_query(auth: SalesforceAuthenticator, api_version: str, pseudo_soql_query: str, output_file: str) -> Tuple[int, int]:
    print(f"🔄 Executing 'ssot' query, writing to {output_file}...")
    skipped_items = []

    try:
        _, instance_url = auth.get_credentials()
        filter_conditions = []
        query_for_api = pseudo_soql_query
        if " WHERE " in pseudo_soql_query.upper():
            query_for_api, where_clause = re.split(" WHERE ", pseudo_soql_query, maxsplit=1, flags=re.IGNORECASE)
            condition_strings = re.split(r'\s+AND\s+', where_clause.strip(), flags=re.IGNORECASE)
            for cond_str in condition_strings:
                match = re.match(r"^\s*([\w.]+)\s*(=|<>)\s*(.+)\s*$", cond_str.strip())
                if match:
                    field, op, value = match.groups()
                    filter_conditions.append({'field': field, 'op': op, 'value': value})
                    print(f"🔍 Client-side filter detected: {field} {op} {value}")
                else:
                    print(f"⚠️ Could not parse condition: '{cond_str}'. Ignoring this part of the filter.")
        
        parts = re.split(" FROM ", query_for_api, flags=re.IGNORECASE)
        select_clause = parts[0].strip()[len('select '):] if parts[0].lower().strip().startswith('select ') else parts[0].strip()
        
        api_fields, header_fields = parse_select_clause_with_aliases(select_clause)
        
        object_name_with_params = parts[1].strip().split(" ")[0]
        base_object_url, params_str = object_name_with_params.split('?', 1) if '?' in object_name_with_params else (object_name_with_params, "")
        params = parse_qs(params_str)
        
        source_iteration_file = params.pop('sourceIteration', [None])[0]
        correlation_field = params.pop('correlationField', [None])[0]
        entry_point = params.pop('entryPoint', [None])[0]
        object_name_for_key = base_object_url
        
        param_names_for_request = params.pop('parameterName', [])
        source_param_columns = params.pop('sourceParameter', [])

        if len(param_names_for_request) != len(source_param_columns):
            print(f"❌ Error: The number of 'parameterName' ({len(param_names_for_request)}) and 'sourceParameter' ({len(source_param_columns)}) attributes must match. Skipping query.")
            return 0, 1
        
        total_rows_written = 0
        
        if source_iteration_file and param_names_for_request and source_param_columns:
            # --- Iterative Mode ---
            full_source_filename = f"{source_iteration_file}.csv"
            source_file_path = os.path.join(OUTPUT_DIRECTORY, full_source_filename)
            print(f"▶️  Entering iterative mode based on source file: '{full_source_filename}'")
            try:
                with open(source_file_path, mode='r', encoding='utf-8') as infile:
                    all_source_rows = list(csv.DictReader(infile))
                rows_to_iterate = all_source_rows
                if filter_conditions:
                    print(f"🔍 Applying WHERE clause to source file '{full_source_filename}'...")
                    rows_to_iterate = apply_client_side_filter(all_source_rows, filter_conditions)
                
                unique_rows_to_process = []
                seen_combinations = set()
                for row in rows_to_iterate:
                    combination_key = tuple(row.get(col, '').strip() for col in source_param_columns)
                    if combination_key not in seen_combinations:
                        seen_combinations.add(combination_key)
                        unique_rows_to_process.append(row)
                
                print(f"🔍 Found {len(rows_to_iterate)} filtered source rows, processing {len(unique_rows_to_process)} unique parameter combinations.")
                last_processed_value = None
                file_exists = os.path.exists(output_file)
                if file_exists:
                    try:
                        with open(output_file, mode='r', encoding='utf-8') as infile:
                            reader = csv.DictReader(infile)
                            if correlation_field and correlation_field in reader.fieldnames:
                                for row in reader:
                                    last_processed_value = row[correlation_field]
                                if last_processed_value:
                                    print(f"🔍 Found last processed value '{last_processed_value}' in '{output_file}' using column '{correlation_field}'. Resuming.")
                            else:
                                print(f"⚠️ Cannot resume: correlation column '{correlation_field}' not found. Starting fresh.")
                                file_exists = False
                    except Exception as e:
                        print(f"⚠️ Could not read existing output file to resume: {e}. Starting fresh.")
                        file_exists = False
                
                final_rows_to_process = unique_rows_to_process
                if last_processed_value:
                    try:
                        correlation_values = [row.get(correlation_field) for row in unique_rows_to_process]
                        last_index = len(correlation_values) - 1 - correlation_values[::-1].index(last_processed_value)
                        final_rows_to_process = unique_rows_to_process[last_index + 1:]
                    except (ValueError, TypeError):
                         print(f"⚠️ Last processed value '{last_processed_value}' not found in the unique source list. Starting fresh.")
                         file_exists = False
                
                print(f"Found {len(final_rows_to_process)} items to process. Starting parallel execution with {MAX_WORKERS} workers...")
                file_mode = 'a' if file_exists else 'w'
                
                with open(output_file, mode=file_mode, newline='', encoding='utf-8') as csvfile:
                    csv_writer = csv.DictWriter(csvfile, fieldnames=header_fields, extrasaction='ignore')
                    if not file_exists or os.path.getsize(output_file) == 0:
                        csv_writer.writeheader()
                    
                    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                        future_to_row = {
                            executor.submit(
                                fetch_ssot_for_row,
                                auth, api_version, base_object_url, row, params,
                                param_names_for_request, source_param_columns,
                                entry_point, object_name_for_key, api_fields, header_fields
                            ): row for row in final_rows_to_process
                        }
                        
                        for future in tqdm(as_completed(future_to_row), total=len(final_rows_to_process), desc="Processing Items"):
                            source_row_info = future_to_row[future]
                            result_rows = future.result()
                            
                            if result_rows is not None:
                                if result_rows:
                                    csv_writer.writerows(result_rows)
                                    total_rows_written += len(result_rows)
                            else:
                                skipped_items.append((str(source_row_info), "Worker failed", datetime.now().isoformat()))

            except FileNotFoundError: print(f"❌ Iteration source file not found: {source_file_path}. Skipping.")
            except KeyError as e: print(f"❌ Source parameter column '{e}' not found in '{source_file_path}'. Skipping.")
        else:
            # --- Standard SSOT Mode ---
            query_string = urlencode(params, doseq=True)
            request_url = f"{instance_url}/services/data/{api_version}/ssot/{base_object_url}?{query_string}"
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                csv_writer = csv.DictWriter(csvfile, fieldnames=header_fields, extrasaction='ignore')
                csv_writer.writeheader()
                page_generator = stream_all_ssot_pages(auth, request_url, entry_point, object_name_for_key, api_fields, filter_conditions)
                for page_of_rows in page_generator:
                    if page_of_rows:
                        sanitized_rows = sanitize_csv_rows(page_of_rows)
                        aliased_rows = rename_record_keys(sanitized_rows, api_fields, header_fields)
                        csv_writer.writerows(aliased_rows)
                        total_rows_written += len(aliased_rows)
        
        if skipped_items:
            skipped_file_path = os.path.splitext(output_file)[0] + ".skipped"
            with open(skipped_file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['timestamp', 'value', 'reason'])
                for value, reason, timestamp in skipped_items:
                    writer.writerow([timestamp, value, reason])
            print(f"⚠️ Wrote {len(skipped_items)} skipped items to {skipped_file_path}")

        if total_rows_written > 0:
            print(f"\n✅ Successfully wrote a total of {total_rows_written} rows to {output_file}")
        else:
            if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
                 with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                    csv_writer = csv.DictWriter(csvfile, fieldnames=header_fields, extrasaction='ignore')
                    csv_writer.writeheader()
            print("✅ Query returned no records to write.")
        return total_rows_written, len(skipped_items)
    except Exception as e:
        print(f"❌ An error occurred during SSOT query execution: {e}")
        return 0, 0


# --- Local Parse & Search Functions ---

def execute_local_parse_query(query: str, output_file: str) -> Tuple[int, int]:
    print(f"🔄 Executing 'localParse' query, writing to {output_file}...")
    all_final_rows = []
    try:
        select_clause = query.split(" FROM ")[0][len('select '):].strip()
        from_clause = query.split(" FROM ")[1]
        api_fields, header_fields = parse_select_clause_with_aliases(select_clause)
        from_and_where = from_clause.split(" WHERE ")
        source_file_base = from_and_where[0].strip()
        alias_map = {}
        if len(from_and_where) > 1:
            alias_definitions = from_and_where[1].split(" AND ")
            for definition in alias_definitions:
                match = re.match(r"^\s*(\w+)\s+IS\s+([\w.]+)\s*$", definition.strip())
                if match:
                    alias, source_column = match.groups()
                    alias_map[alias] = source_column
        if not alias_map:
            print("❌ 'localParse' query requires a 'WHERE' clause with 'IS' aliases. Skipping.")
            return 0, 0

        source_filename = f"{source_file_base}.csv"
        source_filepath = os.path.join(OUTPUT_DIRECTORY, source_filename)
        print(f"▶️  Reading local source file: '{source_filepath}'")
        with open(source_filepath, mode='r', encoding='utf-8') as infile:
            reader = csv.DictReader(infile)
            for i, source_row in enumerate(reader):
                aliased_fields_map = {}
                base_fields = []
                for f in api_fields:
                    is_aliased = False
                    for alias in alias_map.keys():
                        if f.startswith(alias + '.'):
                            if alias not in aliased_fields_map: aliased_fields_map[alias] = []
                            aliased_fields_map[alias].append(f)
                            is_aliased = True; break
                    if not is_aliased: base_fields.append(f)
                base_row_data = {f: source_row.get(f, '') for f in base_fields}
                aliased_results = {}
                for alias, fields in aliased_fields_map.items():
                    source_col_name = alias_map[alias]
                    source_string = source_row.get(source_col_name, "")
                    for field in fields:
                        key_to_find = field.split('.')[-1]
                        regex = rf'"{key_to_find}"\s*:\s*"([^"]*)"'
                        matches = re.findall(regex, source_string)
                        aliased_results[field] = matches
                max_rows = max(len(v) for v in aliased_results.values()) if aliased_results else 0
                if max_rows == 0:
                    new_row = base_row_data.copy()
                    for fields in aliased_fields_map.values():
                        for field in fields: new_row[field] = ''
                    all_final_rows.append(new_row)
                else:
                    for i in range(max_rows):
                        new_row = base_row_data.copy()
                        for field, matches in aliased_results.items():
                            new_row[field] = matches[i] if i < len(matches) else ''
                        all_final_rows.append(new_row)
        if all_final_rows:
            unique_rows_set = set(frozenset(row.items()) for row in all_final_rows)
            all_final_rows = [dict(s) for s in unique_rows_set]
        
        if not all_final_rows:
            print("✅ Query returned no records after parsing.")
            return 0, 0
            
        sanitized_rows = sanitize_csv_rows(all_final_rows)
        aliased_rows = rename_record_keys(sanitized_rows, api_fields, header_fields)
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            csv_writer = csv.DictWriter(csvfile, fieldnames=header_fields, extrasaction='ignore')
            csv_writer.writeheader()
            csv_writer.writerows(aliased_rows)
        print(f"✅ Successfully wrote {len(aliased_rows)} rows to {output_file}")
        return len(aliased_rows), 0
    except FileNotFoundError:
        print(f"❌ localParse error: The source file '{source_filepath}' was not found.")
        return 0, 0
    except Exception as e:
        print(f"❌ An error occurred during localParse execution: {e}")
        return 0, 0

def execute_local_sql_query(query: str, output_file: str) -> Tuple[int, int]:
    print(f"🔄 Executing 'localSQL' query, writing to {output_file}...")
    all_final_rows = []
    try:
        select_clause = query.split(" FROM ")[0][len('select '):].strip()
        from_clause = query.split(" FROM ")[1]
        api_fields, header_fields = parse_select_clause_with_aliases(select_clause)
        from_and_where = from_clause.split(" WHERE ")
        source_file_base = from_and_where[0].strip()
        alias_map = {}
        if len(from_and_where) > 1:
            alias_definitions = from_and_where[1].split(" AND ")
            for definition in alias_definitions:
                match = re.match(r"^\s*(\w+)\s+IS\s+([\w.]+)\s*$", definition.strip())
                if match:
                    alias, source_column = match.groups()
                    alias_map[alias] = source_column
        if not alias_map:
            print("❌ 'localSQL' query requires a 'WHERE' clause with 'IS' aliases. Skipping.")
            return 0, 0

        source_filename = f"{source_file_base}.csv"
        source_filepath = os.path.join(OUTPUT_DIRECTORY, source_filename)
        print(f"▶️  Reading local source file: '{source_filepath}'")
        with open(source_filepath, mode='r', encoding='utf-8') as infile:
            reader = csv.DictReader(infile)
            for i, source_row in enumerate(reader):
                base_fields = [f for f in api_fields if '.' not in f or not any(f.startswith(alias + '.') for alias in alias_map)]
                base_row_data = {f: source_row.get(f, '') for f in base_fields}
                
                for alias, source_col_name in alias_map.items():
                    sql_string = source_row.get(source_col_name, "")
                    wants_tables = any(f == f'{alias}.table' for f in api_fields)
                    wants_fields = any(f == f'{alias}.field' for f in api_fields)
                    
                    tables = set(re.findall(r'(?:FROM|JOIN)\s+([\w\.]+)', sql_string, re.IGNORECASE))
                    if not tables:
                        new_row = base_row_data.copy()
                        if wants_tables: new_row[f'{alias}.table'] = ''
                        if wants_fields: new_row[f'{alias}.field'] = ''
                        all_final_rows.append(new_row)
                        continue

                    for table in tables:
                        fields_for_table = set(re.findall(rf'\b{re.escape(table)}\.([\w]+)', sql_string, re.IGNORECASE))
                        if not fields_for_table and wants_fields:
                            new_row = base_row_data.copy()
                            if wants_tables: new_row[f'{alias}.table'] = table
                            if wants_fields: new_row[f'{alias}.field'] = ''
                            all_final_rows.append(new_row)
                        else:
                            for field in fields_for_table:
                                new_row = base_row_data.copy()
                                if wants_tables: new_row[f'{alias}.table'] = table
                                if wants_fields: new_row[f'{alias}.field'] = field
                                all_final_rows.append(new_row)

        if all_final_rows:
            unique_rows_set = set(frozenset(row.items()) for row in all_final_rows)
            all_final_rows = [dict(s) for s in unique_rows_set]

        if not all_final_rows:
            print("✅ Query returned no records after parsing.")
            return 0, 0
        
        sanitized_rows = sanitize_csv_rows(all_final_rows)
        aliased_rows = rename_record_keys(sanitized_rows, api_fields, header_fields)
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            csv_writer = csv.DictWriter(csvfile, fieldnames=header_fields, extrasaction='ignore')
            csv_writer.writeheader()
            csv_writer.writerows(aliased_rows)
        print(f"✅ Successfully wrote {len(aliased_rows)} rows to {output_file}")
        return len(aliased_rows), 0
    except FileNotFoundError:
        print(f"❌ localSQL error: The source file '{source_filepath}' was not found.")
        return 0, 0
    except Exception as e:
        print(f"❌ An error occurred during localSQL execution: {e}")
        return 0, 0


# --- Main execution ---
if __name__ == "__main__":
    start_time = time.time()
    total_records_processed = 0
    total_requests_skipped = 0
    
    # --- MODIFIED: Use SalesforceAuthenticator class and load config from .env ---
    auth = SalesforceAuthenticator(SF_LOGIN_URL, SF_CLIENT_ID, SF_USERNAME, SF_PRIVATE_KEY_FILE)
    if not auth.get_credentials():
        print("❌ Halting execution due to initial authentication failure.")
        exit(1)

    try:
        if not os.path.exists(OUTPUT_DIRECTORY):
            os.makedirs(OUTPUT_DIRECTORY)
            print(f"📂 Created output directory: '{OUTPUT_DIRECTORY}'")
    except OSError as e:
        print(f"❌ Error creating directory '{OUTPUT_DIRECTORY}': {e}")
        exit(1)
        
    try:
        with open(QUERY_CONFIG_FILE, mode='r', encoding='utf-8') as infile:
            filtered_lines = (line for line in infile if line.strip() and not line.strip().startswith('#'))
            reader = csv.DictReader(filtered_lines)
            queries = list(reader)

        for row in queries:
            query_type = row.get('queryType', '').strip().lower()
            query_string = row.get('query', '').strip()
            if not query_type or not query_string:
                print("⚠️ Skipping row with missing 'queryType' or 'query'.")
                continue
            try:
                query_for_execution, object_api_name_for_file = "", ""
                if "--" in query_string:
                    query_parts = query_string.split("--")
                    query_for_execution = query_parts[0].strip()
                    object_api_name_for_file = query_parts[1].strip()
                else:
                    query_for_execution = query_string
                    from_clause = re.split(" FROM ", query_string, flags=re.IGNORECASE)[1]
                    where_split = re.split(" WHERE ", from_clause, flags=re.IGNORECASE)
                    full_object_name = where_split[0].strip().split(" ")[0]
                    object_api_name_for_file = full_object_name.split("?")[0]
                file_name = f"{object_api_name_for_file}.csv"
                output_file = os.path.join(OUTPUT_DIRECTORY, file_name)
                print(f"\n{'='*60}\n▶️  Processing query for object: {object_api_name_for_file}\n{'='*60}")
            except IndexError:
                print(f"❌ Could not parse object name from query: '{query_string}'. Skipping.")
                continue
            
            # --- MODIFIED: Pass the 'auth' object to all execution functions ---
            if query_type == "bulk":
                select_clause = query_for_execution.split(' FROM ')[0][len('SELECT '):]
                from_clause = query_for_execution.split(' FROM ')[1]
                api_fields, header_fields = parse_select_clause_with_aliases(select_clause)
                api_soql = f"SELECT {', '.join(api_fields)} FROM {from_clause}"
                job_id = create_bulk_job(auth, SF_API_VERSION, api_soql)
                if job_id:
                    job_state, records_processed = wait_for_job_completion(auth, SF_API_VERSION, job_id, object_api_name_for_file)
                    if job_state in ["JobComplete", "Completed"]:
                        success = download_bulk_results(auth, SF_API_VERSION, job_id, output_file, header_fields)
                        if success: total_records_processed += records_processed
            elif query_type == "job":
                job_id_match = re.search(r'JobId\s*=\s*(\S+)', query_for_execution, re.IGNORECASE)
                if not job_id_match:
                    print(f"❌ Invalid 'job' query format. Expected 'SELECT * FROM Job WHERE JobId = <ID>'. Skipping.")
                    continue
                job_id = job_id_match.group(1).strip()
                print(f"Monitoring existing Bulk Job ID: {job_id}")
                job_state, records_processed = wait_for_job_completion(auth, SF_API_VERSION, job_id, object_api_name_for_file)
                if job_state in ["JobComplete", "Completed"]:
                    success = download_bulk_results(auth, SF_API_VERSION, job_id, output_file)
                    if success: total_records_processed += records_processed
            elif query_type == "standard":
                processed_count = execute_standard_query(auth, SF_API_VERSION, query_for_execution, output_file)
                total_records_processed += processed_count
            elif query_type == "tooling":
                processed_count = execute_tooling_query(auth, SF_API_VERSION, query_for_execution, output_file)
                total_records_processed += processed_count
            elif query_type == "ssot":
                processed_count, skipped_count = execute_ssot_query(auth, SF_API_VERSION, query_for_execution, output_file)
                total_records_processed += processed_count
                total_requests_skipped += skipped_count
            elif query_type == "localparse":
                processed_count, skipped_count = execute_local_parse_query(query_for_execution, output_file)
                total_records_processed += processed_count
                total_requests_skipped += skipped_count
            elif query_type == "localsql":
                processed_count, skipped_count = execute_local_sql_query(query_for_execution, output_file)
                total_records_processed += processed_count
            else:
                print(f"⚠️ Invalid queryType '{row.get('queryType')}' for '{object_api_name_for_file}'. Please use 'Standard', 'Bulk', 'Tooling', 'ssot', 'localParse', or 'localSQL'. Skipping.")
    except FileNotFoundError:
        print(f"❌ Error: The query configuration file '{QUERY_CONFIG_FILE}' was not found.")
        print("Please create this file in the same directory as the script.")
    except Exception as e:
        print(f"❌ An unexpected error occurred: {e}")
    finally:
        end_time = time.time()
        total_time = end_time - start_time
        total_time_minutes = total_time / 60
        print(f"\n{'='*60}\n📋 SUMMARY REPORT\n{'='*60}")
        print(f"Total execution time: {total_time_minutes:.2f} minutes")
        print(f"Total records processed: {total_records_processed}")
        print(f"Total items skipped (API errors or filtered): {total_requests_skipped}")