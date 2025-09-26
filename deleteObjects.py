"""
Este script realiza uma exclusão em massa de objetos do Data Cloud com base em um
arquivo CSV aprovado manualmente.

Version: 3.22 (Correção Definitiva do Payload de Segmento)
- BASE: v3.21
- CORREÇÃO DEFINITIVA (SEGMENT): O payload da exclusão em lote de segmentos foi
  ajustado para replicar EXATAMENTE a estrutura validada via Postman e
  documentação. O script agora usa "type": "Delete" e "Id" (com maiúsculas),
  conforme o formato correto.
"""
import os
import csv
import asyncio
import time
import sys
import logging
import json
from collections import defaultdict

import jwt
import requests
import aiohttp
from dotenv import load_dotenv

# Carrega as variáveis de ambiente do arquivo .env
load_dotenv()

# --- Configuration ---
API_VERSION = "v64.0"
CONCURRENCY_LIMIT = 10
RATE_LIMIT_PER_SECOND = 5
SEGMENT_BATCH_SIZE = 200
PROGRESS_UPDATE_SECONDS = 5

# --- File Paths & Safety Net ---
CSV_FILE_PATH = 'audit_objetos_para_exclusao.csv'
LOG_FILE_PATH = 'deletion_log.txt'
DEBUG_LOG_FILE = 'deletion_debug.log'
SUCCESS_CSV_PATH = 'objetos_sucesso.csv'
FAILURE_CSV_PATH = 'objetos_falha.csv'
MAX_RETRIES = 5
RETRY_DELAY_SECONDS = 300
USE_PROXY = True
PROXY_URL = os.getenv("PROXY_URL")
VERIFY_SSL = False

class APIPacer:
    # (Classe APIPacer inalterada)
    def __init__(self, rate_limit_per_second: int): self.rate_limit = rate_limit_per_second; self._tokens = asyncio.Queue(rate_limit_per_second); self._refill_task = None
    async def _refill(self):
        while True:
            for _ in range(self.rate_limit):
                if not self._tokens.full(): await self._tokens.put(None)
            await asyncio.sleep(1)
    async def start(self):
        if not self._refill_task: logging.info(f"[PACER] Iniciando o controlador de cadência para {self.rate_limit} reqs/segundo."); self._refill_task = asyncio.create_task(self._refill())
    async def stop(self):
        if self._refill_task: self._refill_task.cancel()
    async def wait(self):
        await self._tokens.get(); self._tokens.task_done()

def setup_logging():
    # (Função setup_logging inalterada)
    logger = logging.getLogger();
    if logger.hasHandlers(): logger.handlers.clear()
    logger.setLevel(logging.DEBUG)
    info_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler_info = logging.FileHandler(LOG_FILE_PATH, mode='w', encoding='utf-8'); file_handler_info.setLevel(logging.INFO); file_handler_info.setFormatter(info_formatter); logger.addHandler(file_handler_info)
    console_handler = logging.StreamHandler(sys.stdout); console_handler.setLevel(logging.INFO); console_handler.setFormatter(info_formatter); logger.addHandler(console_handler)
    debug_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(funcName)s - %(message)s')
    file_handler_debug = logging.FileHandler(DEBUG_LOG_FILE, mode='w', encoding='utf-8'); file_handler_debug.setLevel(logging.DEBUG); file_handler_debug.setFormatter(debug_formatter); logger.addHandler(file_handler_debug)

# --- Funções Auxiliares (get_access_token, etc.) ---
# (Omitidas para brevidade, presentes no bloco de código final)

async def log_progress(progress_counter):
    # (Função log_progress inalterada)
    total_tasks = progress_counter['total']
    if total_tasks == 0: return
    while progress_counter['processed'] < total_tasks:
        processed_count = progress_counter['processed']; percent_complete = (processed_count / total_tasks) * 100
        print(f"\rProgresso: {processed_count}/{total_tasks} tarefas concluídas ({percent_complete:.2f}%)", end="")
        await asyncio.sleep(PROGRESS_UPDATE_SECONDS)
    print(f"\rProgresso: {total_tasks}/{total_tasks} tarefas concluídas (100.00%)")

async def delete_single_record(pacer: APIPacer, session, semaphore, url, item, results_list, progress_counter):
    # (Função delete_single_record inalterada)
    try:
        await pacer.wait()
        retries = 0
        while retries < MAX_RETRIES:
            try:
                async with semaphore:
                    logging.debug(f"Attempting to DELETE URL: {url} (Attempt {retries + 1}/{MAX_RETRIES})")
                    kwargs = {'ssl': VERIFY_SSL, 'proxy': PROXY_URL if USE_PROXY and PROXY_URL else None}
                    async with session.delete(url, **kwargs) as response:
                        response_text = await response.text()
                        if response.status in [200, 204]:
                            logging.info(f"[SUCCESS] Success for '{item.get('DISPLAY_NAME')}': Status={response.status}"); results_list.append({'status': 'success', 'item': item}); return
                        if (response.status == 403 or response.status == 503) and "REQUEST_LIMIT_EXCEEDED" in response_text:
                            retries += 1
                            if retries < MAX_RETRIES: logging.warning(f"[WARNING] API limit reached for '{item.get('DISPLAY_NAME')}'. Pausing for {RETRY_DELAY_SECONDS}s..."); await asyncio.sleep(RETRY_DELAY_SECONDS); continue
                        reason = f"Status: {response.status} - Body: {response_text}"; results_list.append({'status': 'failure', 'item': item, 'reason': reason}); return
            except aiohttp.ClientError as e:
                reason = f"Connection Error: {e}"; results_list.append({'status': 'failure', 'item': item, 'reason': reason}); return
    finally:
        progress_counter['processed'] += 1

async def delete_segment_batch(pacer: APIPacer, session, semaphore, batch_items, results_list, progress_counter):
    try:
        if not batch_items: return
        await pacer.wait()
        
        ## CORREÇÃO DEFINITIVA: Replicando EXATAMENTE a estrutura validada.
        records_payload = [
            {"fields": {"Id": item['DELETION_IDENTIFIER']}}  # <-- "Id" com "I" maiúsculo
            for item in batch_items
        ]

        payload = {
            "allOrNone": False,
            "operations": [{
                "type": "Delete",  # <-- "Delete" com "D" maiúsculo
                "records": records_payload
            }]
        }
        
        endpoint = f"/services/data/{API_VERSION}/ui-api/records/batch"
        logging.info(f"Enviando lote para deletar {len(batch_items)} segmentos.")
        logging.debug(f"[DEBUG] Payload do lote de segmentos: {payload}")
        
        retries = 0
        while retries < MAX_RETRIES:
            try:
                async with semaphore:
                    kwargs = {'ssl': VERIFY_SSL, 'data': json.dumps(payload), 'proxy': PROXY_URL if USE_PROXY and PROXY_URL else None}
                    async with session.post(endpoint, **kwargs) as response:
                        response_text = await response.text()
                        if response.status == 200:
                            response_json = await response.json(content_type=None)
                            for i, result in enumerate(response_json.get("results", [])):
                                item = batch_items[i]
                                if result.get("statusCode") in [200, 204]: results_list.append({'status': 'success', 'item': item})
                                else:
                                    reason = f"Falha no lote. Status do item: {result.get('statusCode')}, Resultado: {result.get('result')}"
                                    results_list.append({'status': 'failure', 'item': item, 'reason': reason})
                            return
                        logging.error(f"[ERROR] A chamada da API de lote falhou com status {response.status}. Resposta: {response_text}")
                        if (response.status == 403 or response.status == 503) and "REQUEST_LIMIT_EXCEEDED" in response_text:
                            retries += 1
                            if retries < MAX_RETRIES: logging.warning(f"[WARNING] Limite de API atingido. Pausando por {RETRY_DELAY_SECONDS}s..."); await asyncio.sleep(RETRY_DELAY_SECONDS); continue
                        reason = f"Falha na chamada da API de lote. Status: {response.status}, Resposta: {response_text}"
                        for item in batch_items: results_list.append({'status': 'failure', 'item': item, 'reason': reason})
                        return
            except aiohttp.ClientError as e:
                reason = f"Connection Error: {e}";
                for item in batch_items: results_list.append({'status': 'failure', 'item': item, 'reason': reason})
                return
    finally:
        progress_counter['processed'] += 1

# --- Lógica Principal e Bloco de Execução ---
# (O código restante é idêntico à versão anterior e foi omitido para brevidade)
# O código completo está no bloco abaixo.
async def main():
    setup_logging()
    objects_to_delete, original_headers = read_and_prepare_csv(CSV_FILE_PATH)
    if not objects_to_delete: return
    if not confirm_deletion(objects_to_delete):
        logging.warning("[CANCELLED] Exclusão cancelada pelo usuário."); return
    auth_data = get_access_token()
    instance_url, access_token = auth_data['instance_url'], auth_data['access_token']
    session_headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
    pacer = APIPacer(rate_limit_per_second=RATE_LIMIT_PER_SECOND)
    await pacer.start()
    results = []
    base_url = f"{instance_url}"
    pending_tasks = []
    grouped_objects = defaultdict(list)
    for item in objects_to_delete: grouped_objects[str(item.get('OBJECT_TYPE', '')).strip().upper().replace(' ', '_')].append(item)
    delete_order = ['ACTIVATION', 'SEGMENT', 'MAPPING', 'CALCULATED_INSIGHT', 'DMO', 'DATA_STREAM']
    for object_type in delete_order:
        items_to_process = grouped_objects.get(object_type, [])
        if not items_to_process: continue
        logging.info(f"Preparando tarefas para {len(items_to_process)} objetos do tipo: {object_type}")
        if object_type == 'SEGMENT':
            for i in range(0, len(items_to_process), SEGMENT_BATCH_SIZE):
                batch = items_to_process[i:i + SEGMENT_BATCH_SIZE]; pending_tasks.append({'type': 'segment_batch', 'batch_items': batch})
        else:
            for item in items_to_process: pending_tasks.append({'type': 'single_record', 'item': item, 'object_type': object_type})
    progress_counter = {'processed': 0, 'total': len(pending_tasks)}
    progress_task = asyncio.create_task(log_progress(progress_counter))
    try:
        async with aiohttp.ClientSession(base_url=base_url, headers=session_headers) as session:
            tasks_to_run = []
            for task_info in pending_tasks:
                if task_info['type'] == 'segment_batch':
                    task = delete_segment_batch(pacer, session, semaphore, task_info['batch_items'], results, progress_counter); tasks_to_run.append(task)
                elif task_info['type'] == 'single_record':
                    item = task_info['item']; object_type = task_info['object_type']
                    id_logic = {'MAPPING': item['ID_OR_API_NAME'], 'DATA_STREAM': item['ID_OR_API_NAME']}
                    identifier = id_logic.get(object_type, item['DELETION_IDENTIFIER'])
                    url_map = {
                        'ACTIVATION': f"/services/data/{API_VERSION}/ssot/activations/{identifier}",
                        'MAPPING': f"/services/data/{API_VERSION}/ssot/data-model-object-mappings/{identifier}",
                        'DATA_STREAM': f"/services/data/{API_VERSION}/ssot/data-streams/{identifier}?shouldDeleteDataLakeObject=true",
                        'CALCULATED_INSIGHT': f"/services/data/{API_VERSION}/ssot/calculated-insights/{identifier}",
                        'DMO': f"/services/data/{API_VERSION}/ssot/data-model-objects/{identifier}"}
                    url = url_map.get(object_type)
                    if url:
                        task = delete_single_record(pacer, session, semaphore, url, item, results, progress_counter); tasks_to_run.append(task)
                    else:
                        progress_counter['processed'] += 1
            await asyncio.gather(*tasks_to_run)
    finally:
        await pacer.stop()
        if progress_task and not progress_task.done():
            progress_task.cancel(); print("\r" + " " * 80 + "\r", end="")
    logging.info("\n--- PROCESSAMENTO CONCLUÍDO ---")
    if original_headers: write_output_csvs(results, original_headers)
    success_count = sum(1 for r in results if r['status'] == 'success')
    failure_count = len(results) - success_count
    print("\n--- RESUMO ---"); print(f"Sucesso: {success_count} | Falhas: {failure_count}")

if __name__ == "__main__":
    def get_access_token():
        logging.info("[AUTH] Authenticating...")
        sf_client_id = os.getenv("SF_CLIENT_ID"); sf_username = os.getenv("SF_USERNAME"); sf_audience = os.getenv("SF_AUDIENCE"); sf_login_url = os.getenv("SF_LOGIN_URL")
        if not all([sf_client_id, sf_username, sf_audience, sf_login_url]): raise ValueError("Missing auth env vars.")
        try:
            with open('private.pem', 'r') as f: private_key = f.read()
        except FileNotFoundError: logging.error("[ERROR] 'private.pem' not found."); raise
        payload = {'iss': sf_client_id, 'sub': sf_username, 'aud': sf_audience, 'exp': int(time.time()) + 300}
        assertion = jwt.encode(payload, private_key, algorithm='RS256')
        params = {'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion': assertion}
        token_url = f"{sf_login_url}/services/oauth2/token"
        proxies = {'http': PROXY_URL, 'https': PROXY_URL} if USE_PROXY and PROXY_URL else None
        res = requests.post(token_url, data=params, proxies=proxies, verify=VERIFY_SSL); res.raise_for_status()
        logging.info("[SUCCESS] Authentication successful."); return res.json()
    def read_and_prepare_csv(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                try:
                    header_line = f.readline()
                    if not header_line: return None, None
                    dialect = csv.Sniffer().sniff(header_line); f.seek(0)
                except csv.Error: f.seek(0)
                reader = csv.DictReader(f, delimiter=dialect.delimiter if 'dialect' in locals() else ',')
                original_headers = [h.strip() for h in reader.fieldnames]
                required = ['DELETAR', 'OBJECT_TYPE', 'DELETION_IDENTIFIER', 'ID_OR_API_NAME']
                if not all(col in original_headers for col in required): logging.error(f"[ERROR] Missing required columns."); return None, None
                f.seek(0); reader = csv.DictReader(f, delimiter=dialect.delimiter if 'dialect' in locals() else ',')
                to_delete = [row for row in reader if str(row.get('DELETAR', '')).strip().upper() == 'SIM']
                return to_delete, original_headers
        except FileNotFoundError: return None, None
    def confirm_deletion(objects_to_delete):
        print("\n--- RESUMO DA EXCLUSÃO ---");
        if not objects_to_delete: return False
        for item in objects_to_delete:
            id_logic = {'MAPPING': item.get('ID_OR_API_NAME'),'DATA_STREAM': item.get('ID_OR_API_NAME')}
            identifier = id_logic.get(item.get('OBJECT_TYPE', '').strip().upper(), item.get('DELETION_IDENTIFIER'))
            print(f"  - TIPO: {item.get('OBJECT_TYPE', 'N/A')}, NOME: {item.get('DISPLAY_NAME', 'N/A')}, ID: {identifier}")
        print(f"\nTotal: {len(objects_to_delete)} objetos"); confirmation = input("Para confirmar, digite 'CONFIRMAR': "); return confirmation.strip().upper() == 'CONFIRMAR'
    def write_output_csvs(results, headers):
        success_items = [r['item'] for r in results if r['status'] == 'success']
        failure_items = []
        for r in results:
            if r['status'] == 'failure':
                item = r['item'].copy(); item['reason_fail'] = r.get('reason', 'Unknown'); failure_items.append(item)
        if success_items:
            with open(SUCCESS_CSV_PATH, 'w', newline='', encoding='utf-8-sig') as f: writer = csv.DictWriter(f, fieldnames=headers); writer.writeheader(); writer.writerows(success_items)
        if failure_items:
            with open(FAILURE_CSV_PATH, 'w', newline='', encoding='utf-8-sig') as f: writer = csv.DictWriter(f, fieldnames=headers + ['reason_fail']); writer.writeheader(); writer.writerows(failure_items)
    
    start_time = time.time()
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.warning("\n[CANCELLED] Operação interrompida pelo usuário.")
    except Exception as e:
        logging.error(f"[FATAL] Um erro inesperado ocorreu: {e}", exc_info=True)
    finally:
        logging.info(f"\nTempo total de execução: {time.time() - start_time:.2f} segundos.")