import socket
import argparse
import logging
import json
import random
import base64
from math import lcm
from Crypto.Cipher import AES

BLOCK_SIZE = 16
MIN_PRIME, MAX_PRIME = 400, 500


# ---------- RSA util ----------
_primalities = [False, False, True]
def create_primality_array(n: int) -> list[int]:
    # 에라토스테네스의 체를 사용하여 2부터 n까지의 소수를 오름차순으로 list 반환
    global _primalities
    if n < 2: return []
    if n < len(_primalities): return [i for i, b in enumerate(_primalities) if b]

    primalities = [False, False] + [True] * (n - 1)
    for p in range(2, int(n ** .5) + 1):
        if not primalities[p]: continue
        for i in range(p * p, n + 1, p): primalities[i] = False
        p += 1

    _primalities = primalities
    return [i for i, b in enumerate(primalities) if b]


def is_prime(n: int) -> bool:   # 소수 판별
    if n < len(_primalities): return _primalities[n]
    return all([p * p < n and n % p != 0 for p in create_primality_array(int(n ** 0.5))])


def prime_factor(n: int) -> set[int]:  # 소인수 분해 (중복 제거)
    if is_prime(n): return {n}

    _n = n
    factors = set()
    for p in create_primality_array(int(n ** 0.5)):
        while _n % p == 0:
            factors.add(p)
            _n //= p
        if _n == 1: return factors

    factors.add(_n)
    return factors


def is_primitive_root(g: int, p: int) -> bool:  # g가 mod p의 원시근(generator)인지 판별
    return is_prime(p) and all([pow(g, (p - 1) // k, p) != 1 for k in prime_factor(p - 1)])


def generate_prime_between(a=MIN_PRIME, b=MAX_PRIME) -> int:  # a와 b 사이의 소수 생성
    while True:
        r = random.randint(a, b)
        if is_prime(r): return r


def generate_rsa_key(a=MIN_PRIME, b=MAX_PRIME) -> tuple[int, int, int, int, int]:  # RSA 암호 키 p, q, n, e, d 생성
    p = generate_prime_between(a, b)
    while True:
        q = generate_prime_between(a, b)
        if p != q: break
    n = p * q
    phi = (p - 1) * (q - 1)

    while True:
        e = random.randint(2, lcm(p - 1, q - 1))
        try:
            d = pow(e, -1, phi)
            break
        except ValueError: continue

    return p, q, n, e, d


def generate_dh_key(a=MIN_PRIME, b=MAX_PRIME) -> tuple[int, int]:  # 디피-헬만 키 생성
    p = generate_prime_between(a, b)
    while True:
        g = random.randint(2, p - 2)
        if is_primitive_root(g, p): break
    return p, g


# ====== encryption ======
# alice_protocol3.py의 코드에서 가져옴


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    rem = len(data) % block_size
    pad_len = block_size - rem if rem != 0 else block_size
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("invalid padding length")
    pad_len = data[-1]
    if not (1 <= pad_len <= block_size):
        raise ValueError("invalid padding value")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid padding pattern")
    return data[:-pad_len]
# 여기까지 가져옴


def aes_encrypt(key, plain_text) -> str:
    aes = AES.new(key, AES.MODE_ECB)
    cipher_text = aes.encrypt(pkcs7_pad(plain_text.encode('utf-8'), BLOCK_SIZE))
    return base64.b64encode(cipher_text).decode('utf-8')


def aes_decrypt(key, cipher_text) -> str:
    aes = AES.new(key, AES.MODE_ECB)
    plain_text = aes.decrypt(base64.b64decode(cipher_text))
    return pkcs7_unpad(plain_text, BLOCK_SIZE).decode('utf-8')


# ====== communication ======


def receive_json(server, timeout=10., buffer_size=4096) -> dict:
    # json dict형으로 받기
    # opcode = -1은 상대가 통신을 종료했으므로 송신하지 않음
    server.settimeout(timeout)

    try:
        received_bytes = server.recv(buffer_size)
        logging.debug(f"[*] Received {len(received_bytes)} bytes from client")
        if not received_bytes:
            logging.error('[*] Received empty bytes. Client seems to have disconnected.')
            return {'opcode': -1, 'error': 'client disconnected'}
        received_str = received_bytes.decode('utf-8').strip()
        logging.info(f'[*] Received: {json.loads(received_str)}')
        return json.loads(received_str)

    except socket.timeout:
        logging.warning('[*] TIMEOUT')
        return {'opcode': 3, 'error': 'timeout'}

    except ConnectionResetError:
        logging.error('[*] ConnectionResetError')
        return {'opcode': -1, 'error': 'connection reset / refused'}

    except json.JSONDecodeError as e:
        logging.error(f'[*] JSONDecodeError: {e}. Received the following str:')
        logging.error(received_str)
        return {'opcode': 3, 'error': 'invalid JSON format'}

    except KeyboardInterrupt:
        logging.warning('[*] KeyboardInterrupt')
        return {'opcode': -1, 'error': 'KeyboardInterrupt'}

    except Exception as e:
        logging.error(f'[*] Exception: {e}')
        return {'opcode': 3, 'error': 'unhandled exception', 'exception': e}


def send_json(server, json_dict: dict):  # json 보내기
    server.send((json.dumps(json_dict)).encode('utf-8'))
    logging.info(f'[*] Sent: {json_dict}')


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's IP address>", help="Bob's IP address", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", metavar="<bob's open port>", help="Bob's port", type=int, required=True)
    # parser.add_argument("-m", "--message", metavar="<message>", help="Message", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args


def run_client_protocol(client: socket.socket):
    random.seed(None)
    p, g = generate_dh_key()
    a = random.randint(2, p - 2)
    aes_key = b'\x00' * 32

    while True:
        received_dict = dict()
        while not received_dict: received_dict = receive_json(client)

        match received_dict['opcode']:

            case 0:
                logging.error(f'[*] THE CODE SHOULD NOT REACH HERE')
                break

            case 1:  # 암호키 전달. 'type': 'DH'가 전제되어 있음
                params = received_dict['parameter']
                p, g = params['p'], params['g']
                server_public_key = received_dict['public']
                logging.info(f'[Alice] DH params <- p={p}, g={g}, B={server_public_key}')

                # (4) 파라미터 검증
                if not (400 <= p <= 500):
                    send_json(client, {"opcode": 3, "error": "incorrect prime range"})
                    raise RuntimeError("p not in [400,500]")
                if not is_prime(p):
                    send_json(client, {"opcode": 3, "error": "incorrect prime number"})
                    raise RuntimeError("p is not prime")
                if not is_primitive_root(g, p):
                    send_json(client, {"opcode": 3, "error": "incorrect generator"})
                    raise RuntimeError("g is not a generator")
                if not (2 <= server_public_key <= p - 2):
                    send_json(client, {"opcode": 3, "error": "invalid public key"})
                    raise RuntimeError("Bob public key out of range")

                # (5) Alice 비밀/공개키 생성 및 전송
                a = random.randint(2, p - 2)
                send_json(client, {
                    'opcode': 1,
                    'type': 'DH',
                    'public': pow(g, a, p)
                })

                # (6) 공유비밀 → AES-ECB-256 키
                aes_key = pow(server_public_key, a, p).to_bytes(2, byteorder='big') * 16
                cipher = AES.new(aes_key, AES.MODE_ECB)
                logging.info("[Alice] derived AES-256 key from DH shared secret")

            case 2:  # 암호화된 메시지 전달. 'type': 'AES'가 전제되어 있음
                # (7) Bob → AES("hello") 수신 & 복호
                server_cipher = received_dict['encryption']
                logging.info(f'[Alice] Decrypted from Bob: “{aes_decrypt(aes_key, server_cipher)}”')
                send_json(client, {
                    'opcode': 2,
                    'type': 'AES',
                    'encryption': aes_encrypt(aes_key, 'world')
                })
                logging.info(f'[Alice] sent AES ciphertext (world)')
                break

            case 3:  # 에러 메시지. alice_protocol3.py에서 가져옴
                send_json(client, received_dict)
            case -1:  # 송신이 끊어졌으니 종료
                break

    client.close()


def main():
    args = parse_args()
    logging.basicConfig(level=args.log.upper())

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.settimeout(10.0)
        client.connect((args.addr, args.port))
        logging.info(f"[Alice] connected to {args.addr}:{args.port}")
        send_json(client, {'opcode': 0, 'type': 'DH'})
        run_client_protocol(client)
    except Exception as e:
        logging.exception(f"[Alice] error: {e}")
    finally:
        try:
            client.close()
        except:
            pass


if __name__ == "__main__":
    main()
