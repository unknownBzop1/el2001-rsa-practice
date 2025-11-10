import socket
import threading
import argparse
import logging
import json
import random
import base64
from typing import Tuple
from math import lcm
from Crypto.Cipher import AES

BLOCK_SIZE = 16
MIN_PRIME, MAX_PRIME = 400, 500


# ---------- RSA util ----------
_primalities = [False, False, True]
def create_primality_array(n: int) -> list[int]:
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


def is_prime(n: int) -> bool:
    if n < len(_primalities): return _primalities[n]
    return all([n % p != 0 for p in create_primality_array(int(n ** 0.5))])


def prime_factor(n: int) -> set[int]:
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


def is_primitive_root(g: int, p: int) -> bool:
    return is_prime(p) and all([pow(g, (p - 1) // k, p) != 1 for k in prime_factor(p - 1)])


def generate_prime_between(a=MIN_PRIME, b=MAX_PRIME) -> int:
    while True:
        r = random.randint(a, b)
        if is_prime(r): return r


def generate_rsa_key(a=MIN_PRIME, b=MAX_PRIME):
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


def generate_dh_key(a=MIN_PRIME, b=MAX_PRIME):
    p = generate_prime_between(a, b)
    while True:
        g = random.randint(2, p - 2)
        if is_primitive_root(g, p): break
    return p, g


# ====== encryption ======


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


def aes_encrypt(key, plain_text):
    aes = AES.new(key, AES.MODE_ECB)
    cipher_text = aes.encrypt(pkcs7_pad(plain_text.encode('utf-8'), BLOCK_SIZE))
    return base64.b64encode(cipher_text).decode('utf-8')


def aes_decrypt(key, cipher_text):
    aes = AES.new(key, AES.MODE_ECB)
    plain_text = aes.decrypt(base64.b64decode(cipher_text))
    return pkcs7_unpad(plain_text, BLOCK_SIZE).decode('utf-8')


# ====== communication ======


def receive_json(client, timeout=10., buffer_size=4096) -> dict:
    client.settimeout(timeout)

    try:
        received_bytes = client.recv(buffer_size)
        logging.debug(f"received {len(received_bytes)} bytes from client")
        if not received_bytes: return dict()
        received_str = received_bytes.decode('utf-8').strip()
        return json.loads(received_str)

    except socket.timeout:
        logging.warning('[*] TIMEOUT')
        return dict()

    except ConnectionResetError:
        logging.error('[*] ConnectionResetError')
        return dict()

    except json.JSONDecodeError as e:
        logging.error(f'[*] JSONDecodeError: {e}. Received the following str:')
        logging.error(received_str)
        return dict()

    except Exception as e:
        logging.error(f'[*] Exception: {e}')
        return dict()


def send_json(client, json_dict: dict):
    client.send((json.dumps(json_dict)).encode('utf-8'))


def run_protocol(client: socket.socket, msg: str):
    random.seed(None)
    p, g = generate_dh_key()
    b = random.randint(2, p - 2)
    aes_key = b'\x00' * 32

    while True:
        received_dict = receive_json(client)
        logging.info(f'[*] received: {received_dict}')

        match received_dict['opcode']:
            case 0:
                p, g = generate_dh_key()
                b = random.randint(2, p - 2)
                send_json(client, {
                    'opcode': 1,
                    'type': 'DH',
                    'public': pow(g, b, p),
                    'parameter': {'p': p, 'g': g}
                })
            case 1:
                client_public_key = received_dict['public']
                aes_key = pow(client_public_key, b, p).to_bytes(2, byteorder='big') * 16
                logging.info(f'[*] aes_key: {pow(client_public_key, b, p)}')
                send_json(client, {
                    'opcode': 2,
                    'type': 'AES',
                    'encryption': aes_encrypt(aes_key, msg)
                })
                logging.info(f'[*] Sent message: “{msg}”')
            case 2:
                client_cipher = received_dict['encryption']
                logging.info(f'[*] Received message: {aes_decrypt(aes_key, client_cipher)}')
            case default:
                break

    client.close()


def run(addr, port, msg):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((addr, port))

    server.listen(10)
    logging.info("[*] Bob is listening on {}:{}".format(addr, port))

    while True:

        try:
            client, client_addr = server.accept()
            logging.info("[*] Bob accepts the connection from {}:{}".format(client_addr[0], client_addr[1]))

            conn_handle = threading.Thread(target=run_protocol, args=(client, msg))
            conn_handle.start()
            conn_handle.join()

        except KeyboardInterrupt:
            logging.info("[*] Bob closed all connections. GOODBYE!")
            break


def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's IP address>", help="Bob's IP address", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", metavar="<bob's open port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-m", "--message", metavar="<message>", help="Message", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args


def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    run(args.addr, args.port, args.message)


if __name__ == "__main__":
    main()
