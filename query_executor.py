#
# Salesforce Bulk, REST, Tooling, & SSOT API Query Program with JWT Bearer Token Authentication
#
# This script performs the following steps:
# 1. Reads a list of queries from a 'QueryConfig.csv' file, skipping commented lines.
# 2. Authenticates with Salesforce using the JWT Bearer Token flow.
# 3. Creates the specified output directory if it does not exist.
# 4. For each query, it executes using the specified API type:
#    a) Bulk API 2.0 ("Bulk"): For very large data sets.
#    b) Standard REST Query API ("Standard"): For smaller to medium data sets.
#    c) Tooling REST Query API ("Tooling"): For querying metadata and developer objects.
#    d) SSOT REST API ("ssot"): For querying SSOT objects via a direct REST endpoint.
#    e) Job Monitoring ("job"): For monitoring an existing Bulk API job and downloading results.
#    f) Local Parse ("localParse"): For parsing and extracting data from existing local CSV files.
#    g) Local SQL ("localSQL"): For extracting table and field names from SQL queries in local CSV files.
# 5. Writes the results for each query to a separate CSV file in the output directory,
#    named dynamically based on the object (e.g., Account_Demo.csv).
#
# Prerequisites:
# - A 'QueryConfig.csv' file in the same directory as this script.
# - A connected app in Salesforce with JWT enabled.
# - A private key file (`server.key` or similar) and a public certificate.
# - Required libraries installed: pip install requests pyjwt cryptography
#

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

# --- Configuration ---
# IMPORTANT: Replace these with your actual values
SF_LOGIN_URL = "https://itauengajamentoworkflow--sfdcenv.sandbox.my.salesforce.com" # Use https://test.salesforce.com for sandbox
SF_API_VERSION = "v64.0"
SF_CLIENT_ID = "3MVG9bjNVlqB8yGFfRe97siPCXcxrH5gwoaTf5.8eT6otwHwvPhYsbpO8OU7sRwoxKHYQ0brU98uyYTM_nZ0g"
SF_USERNAME = "davidmaldonadonaranjo@correio.itau.com.br.sfdcenv"
SF_PRIVATE_KEY_FILE = "sfdcEnv.key"
USE_PROXY = False
PROXY_URL = "http://sfdnoya:080706@proxynew.itau:8080"
VERIFY_SSL = True

# Configuration for query file and output file naming
QUERY_CONFIG_FILE = "QueryConfig.csv"
OUTPUT_DIRECTORY = "ProdSept20"  # The folder to save the output CSV files
OUTPUT_FILE_SUFFIX = "ProdSept20" # e.g., "Account" object becomes "Account_Demo.csv"
RATE_LIMIT_PAUSE_MINUTES = 10 # Minutes to wait upon receiving a 500 error
BULK_JOB_POLL_INTERVAL_SECONDS = 10 # Seconds to wait between Bulk API job status checks

proxies = {'http': PROXY_URL, 'https': PROXY_URL} if USE_PROXY else None

# --- Utility Functions ---

def parse_select_clause_with_aliases(select_clause_str: str) -> Tuple[List[str], List[str]]:
    """
    Parses a SELECT clause, handling field aliases with the 'AS' keyword.

    Args:
        select_clause_str: The string content of the SELECT clause.

    Returns:
        A tuple containing:
        - list_of_api_fields: Field names to use in the actual query.
        - list_of_header_fields: Field names to use as headers in the output CSV.
    """
    api_fields = []
    header_fields = []
    field_definitions = [p.strip() for p in select_clause_str.split(',')]
    
    for definition in field_definitions:
        parts = definition.split(' AS ')
        if len(parts) == 2:
            api_name = parts[0].strip()
            alias_name = parts[1].strip()
            api_fields.append(api_name)
            header_fields.append(alias_name)
        else:
            api_name = definition.strip()
            api_fields.append(api_name)
            header_fields.append(api_name)
            
    return api_fields, header_fields

def rename_record_keys(records: List[Dict], api_fields: List[str], header_fields: List[str]) -> List[Dict]:
    """
    Renames the keys of dictionaries in a list based on a mapping of API fields to header fields.
    """
    if not records or api_fields == header_fields:
        return records

    api_to_header_map = dict(zip(api_fields, header_fields))
    renamed_records = []
    for record in records:
        renamed_record = {api_to_header_map.get(key, key): value for key, value in record.items()}
        renamed_records.append(renamed_record)
    return renamed_records

def authenticate_jwt(login_url: str, client_id: str, username: str, private_key_file: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Authenticates with Salesforce using a JWT Bearer token.
    Returns the access token and instance URL.
    """
    try:
        with open(private_key_file, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=None, backend=default_backend()
            )
        payload = {
            "iss": client_id, "sub": username, "aud": login_url,
            "exp": int(time.time()) + 36000 # 10 hours
        }
        token = jwt.encode(payload, private_key, algorithm="RS256")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": token}
        auth_url = f"{login_url}/services/oauth2/token"
        response = requests.post(auth_url, headers=headers, data=data)
        response.raise_for_status()
        auth_data = response.json()
        print("✅ JWT authentication successful.")
        return auth_data["access_token"], auth_data["instance_url"]
    except FileNotFoundError:
        print(f"❌ Authentication error: Private key file not found at '{private_key_file}'")
    except Exception as e:
        print(f"❌ Error during JWT authentication: {e}")
    return None, None

# --- Bulk Query API Functions ---

def create_bulk_job(access_token: str, instance_url: str, api_version: str, soql_query: str) -> Optional[str]:
    """
    Creates a new Bulk API 2.0 query job. Returns the job ID.
    """
    print(f"🔄 Creating Bulk API job...")
    job_url = f"{instance_url}/services/data/{api_version}/jobs/query"
    headers = {
        "Authorization": f"Bearer {access_token}", "Content-Type": "application/json"
    }
    job_payload = {"operation": "query", "query": soql_query, "contentType": "CSV"}
    try:
        response = requests.post(job_url, headers=headers, data=json.dumps(job_payload), proxies=proxies, verify=VERIFY_SSL)
        response.raise_for_status()
        job_id = response.json()["id"]
        print(f"✅ Job created with ID: {job_id}")
        return job_id
    except requests.exceptions.RequestException as e:
        print(f"❌ Error creating bulk job: {e}")
        return None

def wait_for_job_completion(access_token: str, instance_url: str, api_version: str, job_id: str, object_name: str) -> Tuple[str, int]:
    """
    Polls the job status until it is completed, failed, or aborted.
    Returns the final state and the number of records processed.
    """
    job_status_url = f"{instance_url}/services/data/{api_version}/jobs/query/{job_id}"
    headers = {"Authorization": f"Bearer {access_token}"}
    records_processed = 0
    while True:
        try:
            response = requests.get(job_status_url, headers=headers, proxies=proxies, verify=VERIFY_SSL)
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

def download_bulk_results(access_token: str, instance_url: str, api_version: str, job_id: str, output_file: str, header_fields: Optional[List[str]] = None) -> bool:
    """
    Downloads paginated Bulk API results using the 'Sforce-Locator' header.
    """
    print(f"⬇️ Starting to download Bulk API results to {output_file}...")
    
    initial_results_url = f"{instance_url}/services/data/{api_version}/jobs/query/{job_id}/results"
    next_page_url = initial_results_url
    request_headers = {"Authorization": f"Bearer {access_token}", "Accept-Encoding": "gzip"}
    is_first_page = True

    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as out_f:
            writer = csv.writer(out_f)

            while next_page_url:
                response = requests.get(next_page_url, headers=request_headers, stream=True, proxies=proxies, verify=VERIFY_SSL)
                response.raise_for_status()

                raw_content = response.content
                try:
                    decoded_content = gzip.decompress(raw_content).decode('utf-8')
                except gzip.BadGzipFile:
                    decoded_content = raw_content.decode('utf-8')
                
                lines = decoded_content.strip().splitlines()
                reader = csv.reader(lines)
                
                if is_first_page:
                    print("📦 Processing first page of results...")
                    original_header = next(reader)
                    writer.writerow(header_fields if header_fields else original_header)
                    is_first_page = False
                else:
                    next(reader) # Skip header on subsequent pages
                
                for row in reader:
                    sanitized_row = [' '.join(field.split()) for field in row]
                    writer.writerow(sanitized_row)

                # Check for the next page locator
                locator = response.headers.get('Sforce-Locator')
                if locator and locator.lower() != 'null':
                    next_page_url = f"{initial_results_url}?locator={locator}"
                    print(f"📄 Found next page locator. Fetching more results...")
                else:
                    next_page_url = None # End of results

        print(f"✅ All results pages downloaded, sanitized, and saved to {output_file}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"❌ Error downloading and writing results: {e}")
        return False


# --- CSV Sanitization Helper ---

def sanitize_csv_rows(record_list: List[Dict]) -> List[Dict]:
    """
    Iterates through a list of dictionaries and sanitizes all string values
    to remove newlines and carriage returns.
    """
    for row in record_list:
        for key, value in row.items():
            if isinstance(value, str):
                row[key] = ' '.join(value.split())
    return record_list

# --- Paginated Query (Standard & Tooling) API Functions ---

def flatten_record(record: Dict, parent_key: str = '', sep: str ='.') -> Dict:
    """
    Flattens a nested dictionary, removing 'attributes' key.
    """
    items = []
    for k, v in record.items():
        if k == 'attributes': continue
        new_key = parent_key + sep + k if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_record(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)

def process_paginated_query(access_token: str, instance_url: str, api_version: str, soql_query: str, output_file: str, api_fields: List[str], header_fields: List[str], query_endpoint_template: str) -> int:
    """
    A generic helper function to execute paginated queries, handle aliases, and write to CSV.
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    encoded_query = quote_plus(soql_query)
    query_endpoint = query_endpoint_template.format(api_version=api_version)
    next_records_url = f"/{query_endpoint}?q={encoded_query}"
    
    csv_writer, total_records_fetched, total_size = None, 0, 0
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            while next_records_url:
                try:
                    response = requests.get(f"{instance_url}{next_records_url}", headers=headers, proxies=proxies, verify=VERIFY_SSL)
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
                
                # Rename keys to match header aliases before writing
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

def execute_standard_query(access_token: str, instance_url: str, api_version: str, soql_query: str, output_file: str) -> int:
    print(f"🔄 Executing 'Standard' query, writing to {output_file}...")
    select_clause = soql_query.split(' FROM ')[0][len('SELECT '):]
    from_clause = soql_query.split(' FROM ')[1]
    api_fields, header_fields = parse_select_clause_with_aliases(select_clause)
    api_soql = f"SELECT {', '.join(api_fields)} FROM {from_clause}"
    
    endpoint_template = "services/data/{api_version}/query"
    return process_paginated_query(access_token, instance_url, api_version, api_soql, output_file, api_fields, header_fields, endpoint_template)

def execute_tooling_query(access_token: str, instance_url: str, api_version: str, soql_query: str, output_file: str) -> int:
    print(f"🔄 Executing 'Tooling' query, writing to {output_file}...")
    select_clause = soql_query.split(' FROM ')[0][len('SELECT '):]
    from_clause = soql_query.split(' FROM ')[1]
    api_fields, header_fields = parse_select_clause_with_aliases(select_clause)
    api_soql = f"SELECT {', '.join(api_fields)} FROM {from_clause}"
    
    endpoint_template = "services/data/{api_version}/tooling/query"
    return process_paginated_query(access_token, instance_url, api_version, api_soql, output_file, api_fields, header_fields, endpoint_template)

# --- SSOT & LocalParse API Function Helpers ---

def get_nested_value(record: Dict, path: str) -> Any:
    """
    Retrieves a value from a nested dictionary using a dot-notation path.
    """
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
    """
    Filters a list of records based on a list of WHERE clause conditions.
    A record must match ALL conditions to be included (AND logic).
    """
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
    """
    Recursively expands lists and dictionary keys with wildcards, building partial rows 
    for a given data node.
    """
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
    """
    Flattens records from an SSOT response using a recursive expansion method.
    """
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
    """Helper to search for a key in a nested dict using a list of possible paths."""
    for path in paths:
        value = data
        try:
            for key in path.split('.'): value = value[key]
            return value
        except (KeyError, TypeError, IndexError): continue
    return None

def stream_all_ssot_pages(start_url: str, headers: Dict, instance_url: str, entry_point: str, object_name_for_key: str, api_fields: List[str], filter_conditions: Optional[List[Dict]]) -> Generator[List[Dict], None, None]:
    """
    Handles pagination for an SSOT endpoint and yields pages of processed records as a generator.
    """
    total_size = 0
    parsed_initial_url = urlparse(start_url)
    initial_params = parse_qs(parsed_initial_url.query)
    is_offset_mode = 'offset' in initial_params

    if is_offset_mode:
        print("➡️  Entering offset-based pagination mode.")
        current_offset = int(initial_params.get('offset', ['0'])[0])
        total_fetched_for_offset = 0
        while True:
            url_parts = list(parsed_initial_url); query_params = parse_qs(url_parts[4])
            query_params['offset'] = [str(current_offset)]; url_parts[4] = urlencode(query_params, doseq=True)
            next_request_url = urlunparse(url_parts)
            print(f"Fetching from: {next_request_url}")
            try:
                response = requests.get(next_request_url, headers=headers, proxies=proxies, verify=VERIFY_SSL)
                response.raise_for_status(); result_data = response.json()
            except requests.exceptions.RequestException as e:
                print(f"⚠️ Request failed: {e}. Skipping this request and stopping pagination.")
                return
            records = find_data_in_response(result_data, [entry_point]) if entry_point else (find_data_in_response(result_data, [object_name_for_key.lower()]) or result_data)
            if not isinstance(records, list):
                if isinstance(result_data, dict): records = [result_data]
                elif isinstance(result_data, list): records = result_data
                else: records = []; print(f"❌ Error: Could not find a list or object of records in the response."); break
            if not records:
                print("✅ No more records returned. Ending offset iteration."); break
            if filter_conditions: records = apply_client_side_filter(records, filter_conditions)
            page_rows = flatten_ssot_records(records, api_fields)
            total_fetched_for_offset += len(page_rows)
            print(f"✅ Fetched page with {len(records)} records. Total rows for this request so far: {total_fetched_for_offset}")
            yield page_rows
            current_offset += len(records)
    else:
        next_request_url = start_url
        total_fetched = 0
        while next_request_url:
            print(f"Fetching from: {next_request_url}")
            retry_count = 0
            max_retries = 5
            while retry_count < max_retries:
                try:
                    response = requests.get(next_request_url, headers=headers, proxies=proxies, verify=VERIFY_SSL)
                    response.raise_for_status(); result_data = response.json()
                    break
                except requests.exceptions.HTTPError as e:
                    if e.response.status_code >= 500 and retry_count < max_retries -1:
                        retry_count += 1
                        print(f"⚠️ Server error ({e.response.status_code}) received. Pausing for {RATE_LIMIT_PAUSE_MINUTES} minutes. Retry {retry_count}/{max_retries-1}...")
                        time.sleep(RATE_LIMIT_PAUSE_MINUTES * 60)
                    else:
                        print(f"❌ HTTP Error: {e}. Skipping this request and stopping pagination."); return
                except requests.exceptions.RequestException as e:
                    print(f"⚠️ Request failed: {e}. Skipping this request and stopping pagination."); return
            if retry_count == max_retries:
                print(f"❌ Max retries reached for {next_request_url}. Skipping."); return
            records = find_data_in_response(result_data, [entry_point]) if entry_point else (find_data_in_response(result_data, [object_name_for_key.lower()]) or result_data)
            if not isinstance(records, list):
                if isinstance(result_data, dict): records = [result_data]
                elif isinstance(result_data, list): records = result_data
                else: records = []; print(f"❌ Error: Could not find a list or object of records in the response."); break
            if filter_conditions: records = apply_client_side_filter(records, filter_conditions)
            if total_size == 0:
                total_size = find_data_in_response(result_data, ['totalSize', 'total', 'collection.totalSize', 'collection.total']) or 0
            next_page_relative_url = find_data_in_response(result_data, ['nextPageUrl', 'collection.nextPageUrl'])
            if not records and total_fetched > 0:
                print("✅ No more records returned. Ending iteration."); break
            page_rows = flatten_ssot_records(records, api_fields)
            total_fetched += len(page_rows)
            progress_msg = f"✅ Fetched page with {len(records)} records. Total rows for this request so far: {total_fetched}"
            if total_size and isinstance(total_size, int) and total_size > 0: progress_msg += f" of {total_size}"
            print(progress_msg)
            yield page_rows
            if not records and total_fetched == 0 and not next_page_relative_url: break
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

def execute_ssot_query(access_token: str, instance_url: str, api_version: str, pseudo_soql_query: str, output_file: str) -> Tuple[int, int]:
    """
    Executes a query against the SSOT REST endpoint, handling aliases, pagination, and iteration.
    """
    print(f"🔄 Executing 'ssot' query, writing to {output_file}...")
    headers = {"Authorization": f"Bearer {access_token}"}
    skipped_items = []

    try:
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
            full_source_filename = f"{source_iteration_file}_{OUTPUT_FILE_SUFFIX}.csv"
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
                            if correlation_field in reader.fieldnames:
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
                
                print(f"Found {len(final_rows_to_process)} items to process (after resuming).")
                file_mode = 'a' if file_exists else 'w'
                with open(output_file, mode=file_mode, newline='', encoding='utf-8') as csvfile:
                    csv_writer = csv.DictWriter(csvfile, fieldnames=header_fields, extrasaction='ignore')
                    if not file_exists:
                        csv_writer.writeheader()
                    for i, row in enumerate(final_rows_to_process):
                        iter_params = params.copy()
                        base_url_for_iter = f"{instance_url}/services/data/{api_version}/ssot/{base_object_url}"
                        if len(param_names_for_request) == 1 and param_names_for_request[0] == '/':
                            value = row.get(source_param_columns[0], '')
                            base_url_for_iter = f"{base_url_for_iter}/{value}"
                            print(f"\n--- Iteration {i+1}/{len(final_rows_to_process)} for path value: '{value}' ---")
                        else:
                            for param_name, source_col in zip(param_names_for_request, source_param_columns):
                                value = row.get(source_col, '')
                                iter_params[param_name] = [value]
                            print(f"\n--- Iteration {i+1}/{len(final_rows_to_process)} for params: {iter_params} ---")
                        
                        query_string_for_iter = urlencode(iter_params, doseq=True)
                        start_url = f"{base_url_for_iter}?{query_string_for_iter}" if query_string_for_iter else base_url_for_iter
                        try:
                            page_generator = stream_all_ssot_pages(start_url, headers, instance_url, entry_point, object_name_for_key, api_fields, None)
                            for page_of_rows in page_generator:
                                if page_of_rows:
                                    sanitized_rows = sanitize_csv_rows(page_of_rows)
                                    aliased_rows = rename_record_keys(sanitized_rows, api_fields, header_fields)
                                    csv_writer.writerows(aliased_rows)
                                    total_rows_written += len(aliased_rows)
                        except Exception:
                            skipped_items.append((str(iter_params), "API request failed", datetime.now().isoformat()))
            except FileNotFoundError: print(f"❌ Iteration source file not found: {source_file_path}. Skipping.")
            except KeyError as e: print(f"❌ Source parameter column '{e}' not found in '{source_file_path}'. Skipping.")
        else:
            # --- Standard SSOT Mode ---
            query_string = urlencode(params, doseq=True)
            request_url = f"{instance_url}/services/data/{api_version}/ssot/{base_object_url}?{query_string}"
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                csv_writer = csv.DictWriter(csvfile, fieldnames=header_fields, extrasaction='ignore')
                csv_writer.writeheader()
                page_generator = stream_all_ssot_pages(request_url, headers, instance_url, entry_point, object_name_for_key, api_fields, filter_conditions)
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

        source_filename = f"{source_file_base}_{OUTPUT_FILE_SUFFIX}.csv"
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
            print(f"Found {len(all_final_rows)} rows before deduplication.")
            unique_rows_set = set()
            deduplicated_rows = []
            for row in all_final_rows:
                row_tuple = frozenset(row.items())
                if row_tuple not in unique_rows_set:
                    unique_rows_set.add(row_tuple)
                    deduplicated_rows.append(row)
            all_final_rows = deduplicated_rows
            print(f"Found {len(all_final_rows)} unique rows after deduplication.")
        if not all_final_rows:
            print("✅ Query returned no records after parsing and deduplication.")
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

        source_filename = f"{source_file_base}_{OUTPUT_FILE_SUFFIX}.csv"
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
                for alias, fields in aliased_fields_map.items():
                    source_col_name = alias_map[alias]
                    sql_string = source_row.get(source_col_name, "")
                    wants_tables = any(f.endswith('.table') for f in fields)
                    wants_fields = any(f.endswith('.field') for f in fields)
                    if wants_tables and wants_fields:
                        tables = set(re.findall(r'(?:FROM|JOIN)\s+([\w\.]+)', sql_string, re.IGNORECASE))
                        if not tables:
                            new_row = base_row_data.copy()
                            new_row[f'{alias}.table'] = ''; new_row[f'{alias}.field'] = ''
                            all_final_rows.append(new_row)
                        for table in tables:
                            fields_for_table = set(re.findall(rf'{re.escape(table)}\.([\w]+)', sql_string, re.IGNORECASE))
                            if not fields_for_table:
                                new_row = base_row_data.copy()
                                new_row[f'{alias}.table'] = table; new_row[f'{alias}.field'] = ''
                                all_final_rows.append(new_row)
                            else:
                                for field in fields_for_table:
                                    new_row = base_row_data.copy()
                                    new_row[f'{alias}.table'] = table; new_row[f'{alias}.field'] = field
                                    all_final_rows.append(new_row)
                    elif wants_tables:
                        tables = set(re.findall(r'(?:FROM|JOIN)\s+([\w\.]+)', sql_string, re.IGNORECASE))
                        if not tables: all_final_rows.append(base_row_data)
                        for table in tables:
                            new_row = base_row_data.copy()
                            new_row[f'{alias}.table'] = table
                            all_final_rows.append(new_row)
                    elif wants_fields:
                        fields_found = set(re.findall(r'([\w]+\.[\w]+)', sql_string))
                        if not fields_found: all_final_rows.append(base_row_data)
                        for field in fields_found:
                            new_row = base_row_data.copy()
                            new_row[f'{alias}.field'] = field
                            all_final_rows.append(new_row)
        if all_final_rows:
            print(f"Found {len(all_final_rows)} rows before deduplication.")
            unique_rows_set = set()
            deduplicated_rows = []
            for row in all_final_rows:
                row_tuple = frozenset(row.items())
                if row_tuple not in unique_rows_set:
                    unique_rows_set.add(row_tuple)
                    deduplicated_rows.append(row)
            all_final_rows = deduplicated_rows
            print(f"Found {len(all_final_rows)} unique rows after deduplication.")
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
    access_token, instance_url = authenticate_jwt(SF_LOGIN_URL, SF_CLIENT_ID, SF_USERNAME, SF_PRIVATE_KEY_FILE)
    if not access_token: exit(1)
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
            for row in reader:
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
                    file_name = f"{object_api_name_for_file}_{OUTPUT_FILE_SUFFIX}.csv"
                    output_file = os.path.join(OUTPUT_DIRECTORY, file_name)
                    print(f"\n{'='*60}\n▶️  Processing query for object: {object_api_name_for_file}\n{'='*60}")
                except IndexError:
                    print(f"❌ Could not parse object name from query: '{query_string}'. Skipping.")
                    continue
                if query_type == "bulk":
                    select_clause = query_for_execution.split(' FROM ')[0][len('SELECT '):]
                    from_clause = query_for_execution.split(' FROM ')[1]
                    api_fields, header_fields = parse_select_clause_with_aliases(select_clause)
                    api_soql = f"SELECT {', '.join(api_fields)} FROM {from_clause}"
                    job_id = create_bulk_job(access_token, instance_url, SF_API_VERSION, api_soql)
                    if job_id:
                        job_state, records_processed = wait_for_job_completion(access_token, instance_url, SF_API_VERSION, job_id, object_api_name_for_file)
                        if job_state in ["JobComplete", "Completed"]:
                            success = download_bulk_results(access_token, instance_url, SF_API_VERSION, job_id, output_file, header_fields)
                            if success: total_records_processed += records_processed
                elif query_type == "job":
                    job_id_match = re.search(r'JobId\s*=\s*(\S+)', query_for_execution, re.IGNORECASE)
                    if not job_id_match:
                        print(f"❌ Invalid 'job' query format. Expected 'SELECT * FROM Job WHERE JobId = <ID>'. Skipping.")
                        continue
                    job_id = job_id_match.group(1).strip()
                    print(f"Monitoring existing Bulk Job ID: {job_id}")
                    job_state, records_processed = wait_for_job_completion(access_token, instance_url, SF_API_VERSION, job_id, object_api_name_for_file)
                    if job_state in ["JobComplete", "Completed"]:
                        success = download_bulk_results(access_token, instance_url, SF_API_VERSION, job_id, output_file)
                        if success: total_records_processed += records_processed
                elif query_type == "standard":
                    processed_count = execute_standard_query(access_token, instance_url, SF_API_VERSION, query_for_execution, output_file)
                    total_records_processed += processed_count
                elif query_type == "tooling":
                    processed_count = execute_tooling_query(access_token, instance_url, SF_API_VERSION, query_for_execution, output_file)
                    total_records_processed += processed_count
                elif query_type == "ssot":
                    processed_count, skipped_count = execute_ssot_query(access_token, instance_url, SF_API_VERSION, query_for_execution, output_file)
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