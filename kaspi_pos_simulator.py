import json
import time
import logging
import datetime
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("kaspi_pos_simulator.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("KaspiPOSSimulator")


MOCK_DATA = {
    "storeName": "Тестовый магазин",
    "city": "г. Алматы",
    "address": "Конаева 11, 6",
    "bin": "960419351140",
    "terminalId": "31452963",
    "serialNum": "00043010171",
    "posNum": "0"
}


transactions = {}
api_tokens = {}

class KaspiPOSSimulatorHandler(BaseHTTPRequestHandler):
    def _set_headers(self, content_type="application/json", status_code=200):
        self.send_response(status_code)
        self.send_header('Content-type', content_type)
        self.end_headers()
    
    def _handle_error(self, status_code, error_text):
        logger.error(f"Error: {error_text} (Code: {status_code})")
        self._set_headers(status_code=status_code)
        response = {
            "errorText": error_text,
            "statusCode": status_code
        }
        self.wfile.write(json.dumps(response).encode())
    
    def _validate_access_token(self):
        if not hasattr(self.server, 'secure_api') or not self.server.secure_api:
            return True
        
        headers_str = "\n".join([f"{k}: {v}" for k, v in self.headers.items()])
        logger.info(f"Request headers:\n{headers_str}")
        
        token = None
        
        if not token:
            for header_name, header_value in self.headers.items():
                if header_name.lower() == 'accesstoken':
                    token = header_value
                    break
        
        if not token:
            parsed_url = urlparse(self.path)
            query_params = parse_qs(parsed_url.query)
            if 'accesstoken' in query_params:
                token = query_params['accesstoken'][0]
        
        if not token:
            logger.error("Token not found in headers or query parameters")
            return False
        
        logger.info(f"Found token: {token}")
        
        if token in api_tokens:
            if datetime.datetime.now() < api_tokens[token]['expiration']:
                logger.info(f"Token is valid, expires at {api_tokens[token]['expiration']}")
                return True
            else:
                logger.error(f"Token expired at {api_tokens[token]['expiration']}")
        else:
            logger.error(f"Token not found in known tokens")
            known_tokens = ", ".join(api_tokens.keys())
            logger.error(f"Known tokens: {known_tokens}")
        
        return False
    
    def do_GET(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        
        query_params = parse_qs(parsed_url.query)
        params = {k: v[0] for k, v in query_params.items()}
        
        logger.info(f"Path: {path}, Params: {params}")
        
        if path != '/v2/register' and path != '/v2/reset' and hasattr(self.server, 'secure_api') and self.server.secure_api:
            if not self._validate_access_token():
                self._handle_error(401, "Authorization failed")
                return
        
        if path == '/v2/payment':
            self._handle_payment(params)
        elif path == '/v2/refund':
            self._handle_refund(params)
        elif path == '/v2/status':
            self._handle_status(params)
        elif path == '/v2/actualize':
            self._handle_actualize(params)
        elif path == '/v2/deviceinfo':
            self._handle_device_info()
        elif path == '/v2/register':
            self._handle_register(params)
        elif path == '/v2/revoke':
            self._handle_revoke(params)
        elif path == '/v2/reset':
            self._handle_reset(params)
        else:
            self._handle_error(404, "Invalid Url. Please, contact developers")
    
    def _check_and_clear_stuck_transactions(self):
        global transactions
        
        now = datetime.datetime.now()
        
        to_delete = []
        
        for process_id, transaction in transactions.items():
            if transaction['status'] == 'wait':
                elapsed_time = (now - transaction['createTime']).total_seconds()
                if elapsed_time > 120:  # 2 минуты тайм-аут
                    to_delete.append(process_id)
                    logger.info(f"Clearing stuck transaction {process_id}, elapsed time: {elapsed_time} seconds")
            
            elif transaction['status'] in ['success', 'fail', 'unknown']:
                if 'completedTime' not in transaction:
                    transaction['completedTime'] = now
                
                elapsed_since_completion = (now - transaction['completedTime']).total_seconds()
                if elapsed_since_completion > 1800:  # 30 минут
                    to_delete.append(process_id)
                    logger.info(f"Clearing completed transaction {process_id}, elapsed since completion: {elapsed_since_completion} seconds")
        
        for process_id in to_delete:
            del transactions[process_id]
        
        return len(to_delete) > 0
    
    def _handle_payment(self, params):
        self._check_and_clear_stuck_transactions()
        
        if 'amount' not in params:
            self._handle_error(999, "Missing param: amount")
            return
        
        try:
            amount = int(params['amount'])
            if amount <= 0:
                self._handle_error(999, "Param unvalidated: amount. Must be greater 0")
                return
        except ValueError:
            self._handle_error(999, "Param unvalidated: amount. Must be a number")
            return
        
        active_processes = [p for p in transactions.values() if p['status'] == 'wait']
        if active_processes:
            for process in active_processes:
                elapsed_time = (datetime.datetime.now() - process['createTime']).total_seconds()
                if elapsed_time > 300:  # 5 минут
                    process['status'] = 'fail'
                    process['message'] = "Timeout exceeded"
                    process['completedTime'] = datetime.datetime.now()
                    logger.info(f"Force completing stuck transaction {process['processId']} after {elapsed_time} seconds")
                else:
                    self._handle_error(107, "Could not register transaction. Last operation was not completed.")
                    return
        
        process_id = str(int(time.time() * 1000))
        
        transactions[process_id] = {
            'processId': process_id,
            'status': 'wait',
            'subStatus': 'Initialize',
            'amount': amount,
            'createTime': datetime.datetime.now(),
            'owncheque': params.get('owncheque', 'false').lower() == 'true',
        }
        
        self._set_headers()
        response = {
            "data": {
                "processId": process_id,
                "status": "wait"
            },
            "statusCode": 0
        }
        self.wfile.write(json.dumps(response).encode())

    def _handle_refund(self, params):
        self._check_and_clear_stuck_transactions()
        
        required_params = ['amount', 'method', 'transactionId']
        for param in required_params:
            if param not in params:
                self._handle_error(999, f"Missing param: {param}")
                return
        
        try:
            amount = int(params['amount'])
            if amount <= 0:
                self._handle_error(999, "Param unvalidated: amount. Must be greater 0")
                return
        except ValueError:
            self._handle_error(999, "Param unvalidated: amount. Must be a number")
            return
        
        method = params['method']
        if method not in ['qr', 'card']:
            self._handle_error(999, "Param unvalidated: method. Unknown payment method")
            return
        
        active_processes = [p for p in transactions.values() if p['status'] == 'wait']
        if active_processes:
            for process in active_processes:
                elapsed_time = (datetime.datetime.now() - process['createTime']).total_seconds()
                if elapsed_time > 300:  # 5 минут
                    process['status'] = 'fail'
                    process['message'] = "Timeout exceeded"
                    process['completedTime'] = datetime.datetime.now()
                    logger.info(f"Force completing stuck transaction {process['processId']} after {elapsed_time} seconds")
                else:
                    self._handle_error(107, "Could not register transaction. Last operation was not completed.")
                    return
        
        process_id = str(int(time.time() * 1000))
        
        transactions[process_id] = {
            'processId': process_id,
            'status': 'wait',
            'subStatus': 'Initialize',
            'amount': amount,
            'method': method,
            'transactionId': params['transactionId'],
            'createTime': datetime.datetime.now(),
            'owncheque': params.get('owncheque', 'false').lower() == 'true',
            'type': 'refund'
        }
        
        self._set_headers()
        response = {
            "data": {
                "processId": process_id,
                "status": "wait"
            },
            "statusCode": 0
        }
        self.wfile.write(json.dumps(response).encode())

    def _handle_status(self, params):
        if 'processId' not in params:
            self._handle_error(999, "Missing param: processId")
            return
        
        process_id = params['processId']
        
        if process_id not in transactions:
            self._handle_error(101, "Process not found")
            return
        
        transaction = transactions[process_id]
        
        elapsed_time = (datetime.datetime.now() - transaction['createTime']).total_seconds()
        
        if transaction['status'] == 'wait':
            if elapsed_time < 2:
                transaction['subStatus'] = 'WaitUser'
            elif elapsed_time < 4:
                if transaction.get('type') == 'refund':
                    transaction['subStatus'] = 'ProcessRefund'
                else:
                    import random
                    is_qr = random.choice([True, False])
                    transaction['method'] = 'qr' if is_qr else 'card'
                    
                    if is_qr:
                        transaction['subStatus'] = 'WaitForQrConfirmation'
                    else:
                        transaction['subStatus'] = 'ProcessingCard'
            elif elapsed_time < 6:
                transaction['status'] = 'success'
                
                if transaction.get('type') == 'refund':
                    if transaction['method'] == 'qr':
                        transaction['subStatus'] = 'QrTransactionSuccess'
                        transaction['orderNumber'] = str(uuid.uuid4().int)[:9]
                        transaction['transactionId'] = transaction['orderNumber']
                    else:
                        transaction['subStatus'] = 'CardTransactionSuccess'
                        transaction['rrn'] = str(uuid.uuid4().int)[:12]
                        transaction['authorizationCode'] = str(uuid.uuid4().int)[:6]
                        transaction['transactionId'] = transaction['rrn']
                        transaction['cardMask'] = f"440043******{str(uuid.uuid4().int)[:4]}"
                else:
                    if transaction['method'] == 'qr':
                        transaction['subStatus'] = 'QrTransactionSuccess'
                        transaction['orderNumber'] = str(uuid.uuid4().int)[:9]
                        transaction['transactionId'] = transaction['orderNumber']
                    else:
                        transaction['subStatus'] = 'CardTransactionSuccess'
                        transaction['rrn'] = str(uuid.uuid4().int)[:12]
                        transaction['authorizationCode'] = str(uuid.uuid4().int)[:6]
                        transaction['hostResponseCode'] = '000'
                        transaction['transactionId'] = transaction['rrn']
                        transaction['cardMask'] = f"440043******{str(uuid.uuid4().int)[:4]}"
                        transaction['icc'] = "Visa Debit"
        
        self._set_headers()
        
        if transaction['status'] == 'success':
            cheque_info = {
                "storeName": MOCK_DATA["storeName"],
                "city": MOCK_DATA["city"],
                "address": MOCK_DATA["address"],
                "bin": MOCK_DATA["bin"],
                "terminalId": MOCK_DATA["terminalId"],
                "date": datetime.datetime.now().strftime("%d.%m.%y %H:%M:%S"),
                "method": transaction['method'],
                "type": transaction.get('type', 'payment')
            }
            
            if transaction['method'] == 'qr':
                amount_value = f"- {transaction['amount']} ₸" if transaction.get('type') == 'refund' else f"{transaction['amount']} ₸"
                cheque_info.update({
                    "amount": amount_value,
                    "orderNumber": transaction['orderNumber'],
                    "status": "Возврат успешно совершен" if transaction.get('type') == 'refund' else "Покупка с Kaspi Gold. Одобрено"
                })
            else: 
                amount_value = f"- {transaction['amount']} ₸" if transaction.get('type') == 'refund' else f"{transaction['amount']} ₸"
                cheque_info.update({
                    "amount": amount_value,
                    "cardMask": transaction['cardMask'],
                    "rrn": transaction['rrn'],
                    "authorizationCode": transaction['authorizationCode'],
                    "status": "Возврат успешно совершен" if transaction.get('type') == 'refund' else "Покупка с Kaspi Gold. Одобрено"
                })
                
                if transaction.get('type') != 'refund':
                    cheque_info.update({
                        "icc": transaction['icc'],
                        "hostResponseCode": transaction['hostResponseCode']
                    })
            
            response = {
                "data": {
                    "processId": process_id,
                    "status": transaction['status'],
                    "subStatus": transaction['subStatus'],
                    "transactionId": transaction['transactionId'],
                    "addInfo": {
                        "IsOffer": False,
                        "LoanTerm": 0,
                        "ProductType": "Gold"
                    },
                    "chequeInfo": cheque_info
                },
                "statusCode": 0
            }
        elif transaction['status'] == 'fail':
            response = {
                "data": {
                    "message": transaction.get('message', "Отмена покупки; Покупатель отменил покупку"),
                    "processId": process_id,
                    "status": "fail",
                    "subStatus": transaction['subStatus']
                },
                "statusCode": 0
            }
        elif transaction['status'] == 'unknown':
            response = {
                "data": {
                    "message": transaction.get('message', "Операция отменена"),
                    "processId": process_id,
                    "status": "unknown",
                    "subStatus": transaction['subStatus']
                },
                "statusCode": 0
            }
        
        if transaction['status'] in ['success', 'fail', 'unknown']:
            transaction['completedTime'] = datetime.datetime.now()

        else: 
            response = {
                "data": {
                    "processId": process_id,
                    "status": "wait",
                    "subStatus": transaction['subStatus']
                },
                "statusCode": 0
            }
        
        self.wfile.write(json.dumps(response).encode())
    
    def _handle_actualize(self, params):
        if 'processId' not in params:
            self._handle_error(999, "Missing param: processId")
            return
        
        process_id = params['processId']
        if process_id not in transactions:
            self._handle_error(101, "Process not found")
            return
        
        transaction = transactions[process_id]
        
        if transaction['status'] != 'unknown':
            self._handle_error(103, "This transaction is unable to actualize")
            return
        
        transaction['status'] = 'success'
        
        if transaction.get('method') == 'qr':
            transaction['subStatus'] = 'QrTransactionSuccess'
            if 'orderNumber' not in transaction:
                transaction['orderNumber'] = str(uuid.uuid4().int)[:9]
                transaction['transactionId'] = transaction['orderNumber']
        else: 
            transaction['subStatus'] = 'CardTransactionSuccess'
            if 'rrn' not in transaction:
                transaction['rrn'] = str(uuid.uuid4().int)[:12]
                transaction['authorizationCode'] = str(uuid.uuid4().int)[:6]
                transaction['hostResponseCode'] = '000'
                transaction['transactionId'] = transaction['rrn']
                transaction['cardMask'] = f"440043******{str(uuid.uuid4().int)[:4]}"
                transaction['icc'] = "Visa Debit"

        self._handle_status(params)
    
    def _handle_device_info(self):
        self._set_headers()
        response = {
            "data": {
                "posNum": MOCK_DATA["posNum"],
                "serialNum": MOCK_DATA["serialNum"],
                "terminalId": MOCK_DATA["terminalId"]
            },
            "statusCode": 0
        }
        print(response)
        self.wfile.write(json.dumps(response).encode())
    
    def _handle_register(self, params):
        if 'name' not in params:
            self._handle_error(999, "Missing param: name")
            return
        
        access_token = uuid.uuid4().hex
        refresh_token = uuid.uuid4().hex
        expiration = datetime.datetime.now() + datetime.timedelta(hours=24)
        
        api_tokens[access_token] = {
            'name': params['name'],
            'refresh_token': refresh_token,
            'expiration': expiration
        }
        
        self._set_headers()
        response = {
            "data": {
                "accessToken": access_token,
                "refreshToken": refresh_token,
                "expirationDate": expiration.strftime("%b %d, %Y %H:%M:%S")
            },
            "statusCode": 0
        }
        self.wfile.write(json.dumps(response).encode())
    
    def _handle_revoke(self, params):
        if 'name' not in params:
            self._handle_error(999, "Missing param: name")
            return
        
        if 'refreshToken' not in params:
            self._handle_error(999, "Param unvalidated: refreshToken. It's empty")
            return

        print(params)
        
        current_token = None
        if 'accesstoken' in self.headers:
            current_token = self.headers['accesstoken']
        
        if not current_token or current_token not in api_tokens:
            self._handle_error(401, "Authorization failed")
            return
        
        if api_tokens[current_token]['name'] != params['name']:
            self._handle_error(105, "Revoke Error. Wrong name")
            return
        
        if api_tokens[current_token]['refresh_token'] != params['refreshToken']:
            self._handle_error(105, "Revoke Error. Wrong refresh token")
            return
        
        new_access_token = uuid.uuid4().hex
        new_refresh_token = uuid.uuid4().hex
        expiration = datetime.datetime.now() + datetime.timedelta(hours=24)
        
        del api_tokens[current_token]
        
        api_tokens[new_access_token] = {
            'name': params['name'],
            'refresh_token': new_refresh_token,
            'expiration': expiration
        }
        
        self._set_headers()
        response = {
            "data": {
                "accessToken": new_access_token,
                "refreshToken": new_refresh_token,
                "expirationDate": expiration.strftime("%b %d, %Y %H:%M:%S")
            },
            "statusCode": 0
        }
        self.wfile.write(json.dumps(response).encode())

    def _handle_reset(self, params):
        global transactions
        
        active_count = len([p for p in transactions.values() if p['status'] == 'wait'])
        total_count = len(transactions)
        
        logger.info(f"Resetting all transactions. Active: {active_count}, Total: {total_count}")

        transactions.clear()
        
        self._set_headers()
        response = {
            "data": {
                "message": f"All transactions have been reset. Active: {active_count}, Total: {total_count}"
            },
            "statusCode": 0
        }
        print(response)
        self.wfile.write(json.dumps(response).encode())


def run(host="0.0.0.0", port=8080, secure_api=False):
    server_address = (host, port)
    httpd = HTTPServer(server_address, KaspiPOSSimulatorHandler)
    httpd.secure_api = secure_api
    
    logger.info(f"Starting Kaspi POS simulator on {host}:{port}")
    if secure_api:
        logger.info("API Security is enabled. You need to register and use tokens for access.")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Stopping Kaspi POS simulator...")
        httpd.server_close()
        logger.info("Server stopped.")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Kaspi POS Terminal Simulator')
    parser.add_argument('--host', type=str, default="0.0.0.0", help='Host to listen on (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8080, help='Port to listen on (default: 8080)')
    parser.add_argument('--secure', action='store_true', help='Enable API security with token authentication')
    
    args = parser.parse_args()
    
    run(host=args.host, port=args.port, secure_api=args.secure)
