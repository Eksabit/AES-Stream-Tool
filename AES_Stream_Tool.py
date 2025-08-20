#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AES-256 GCM streaming encrypt/decrypt + readable password generator + progress bar
Format (binary):
  4 bytes: magic b'AESG'
  1 byte : version (1)
  16 bytes: salt (for KDF, optional; all zeros if not used)
  12 bytes: base_nonce (random)
  4 bytes : chunk_size (uint32, big-endian)
  then sequence of chunks:
    4 bytes: chunk_ciphertext_length (uint32 BE)
    N bytes: ciphertext (ciphertext includes 16-byte tag produced by AESGCM.encrypt)
Notes:
  - Each chunk is encrypted with nonce = base_nonce XOR counter (counter 32-bit in last bytes).
  - Counter starts at 0 and increments per chunk.
  - This approach keeps nonces unique.
Requires: cryptography
pip install cryptography
"""
import os
import sys
import struct
from getpass import getpass
from colorama import Fore, Back, Style, init, just_fix_windows_console
from base64 import urlsafe_b64encode, urlsafe_b64decode
from secrets import token_bytes, choice, randbelow
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import argparse
import string

MAGIC = b'AESG'
VERSION = 1
DEFAULT_CHUNK = 64 * 1024  # 64 KiB

# ---------------- crypto helpers ----------------
def derive_key_from_password(password: str, salt: bytes, length: int = 32) -> bytes:
    kdf = Scrypt(salt=salt, length=length, n=2**14, r=8, p=1)
    return kdf.derive(password.encode('utf-8'))

def generate_key() -> bytes:
    return token_bytes(32)

def save_key_to_file(key: bytes, path: str):
    with open(path, 'wb') as f:
        f.write(key)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass

def load_key_from_file(path: str) -> bytes:
    with open(path, 'rb') as f:
        return f.read()

def xor_nonce(base_nonce: bytes, counter: int) -> bytes:
    # produce nonce by XORing last 4 bytes with counter (big-endian)
    if len(base_nonce) != 12:
        raise ValueError("base_nonce must be 12 bytes")
    counter_bytes = counter.to_bytes(4, 'big')
    return base_nonce[:8] + bytes(a ^ b for a, b in zip(base_nonce[8:], counter_bytes))

# ---------------- streaming encrypt/decrypt ----------------
def encrypt_stream(in_path: str, out_path: str, key: bytes, chunk_size: int = DEFAULT_CHUNK):
    filesize = os.path.getsize(in_path)
    aesgcm = AESGCM(key)
    salt = token_bytes(16)  # stored for possible KDF usage
    base_nonce = token_bytes(12)
    counter = 0

    with open(in_path, 'rb') as inf, open(out_path, 'wb') as outf:
        # header: MAGIC(4) + version(1) + salt(16) + base_nonce(12) + chunk_size(4)
        outf.write(MAGIC)
        outf.write(bytes([VERSION]))
        outf.write(salt)
        outf.write(base_nonce)
        outf.write(struct.pack('>I', chunk_size))

        read = 0
        last_percent = -1
        while True:
            chunk = inf.read(chunk_size)
            if not chunk:
                break
            nonce = xor_nonce(base_nonce, counter)
            ct = aesgcm.encrypt(nonce, chunk, None)  # ct includes 16-byte tag at end
            outf.write(struct.pack('>I', len(ct)))
            outf.write(ct)
            counter += 1
            read += len(chunk)
            # progress
            if filesize > 0:
                percent = int(read * 100 / filesize)
                if percent != last_percent:
                    print_progress(percent)
                    last_percent = percent
        print_progress(100)
    print("\nEncryption done. Chunks:", counter)

def decrypt_stream(in_path: str, out_path: str, key: bytes):
    filesize = os.path.getsize(in_path)
    aesgcm = AESGCM(key)
    with open(in_path, 'rb') as inf, open(out_path, 'wb') as outf:
        header = inf.read(4)
        if header != MAGIC:
            raise ValueError("Bad file format (magic mismatch)")
        version_b = inf.read(1)
        if not version_b:
            raise ValueError("Bad header")
        version = version_b[0]
        if version != VERSION:
            raise ValueError("Unsupported version")
        salt = inf.read(16)
        base_nonce = inf.read(12)
        chunk_size_packed = inf.read(4)
        if len(base_nonce) != 12 or len(chunk_size_packed) != 4:
            raise ValueError("Corrupt header")
        chunk_size = struct.unpack('>I', chunk_size_packed)[0]

        # compute total size for progress: remaining bytes in file
        remaining_total = filesize - (4 + 1 + 16 + 12 + 4)
        read_bytes = 0
        counter = 0
        last_percent = -1
        while True:
            len_packed = inf.read(4)
            if not len_packed:
                break
            if len(len_packed) != 4:
                raise ValueError("Corrupt chunk length")
            ct_len = struct.unpack('>I', len_packed)[0]
            ct = inf.read(ct_len)
            if len(ct) != ct_len:
                raise ValueError("Unexpected EOF while reading ciphertext chunk")
            nonce = xor_nonce(base_nonce, counter)
            pt = aesgcm.decrypt(nonce, ct, None)
            outf.write(pt)
            counter += 1
            read_bytes += 4 + ct_len
            # progress
            if remaining_total > 0:
                percent = int(read_bytes * 100 / remaining_total)
                if percent != last_percent:
                    print_progress(percent)
                    last_percent = percent
        print_progress(100)
    print("\nDecryption done. Chunks:", counter)

# ---------------- progress bar ----------------
def print_progress(percent: int):
    bar_len = 40
    filled = int(bar_len * percent // 100)
    bar = '=' * filled + ' ' * (bar_len - filled)
    print(f"\r[{bar}] {percent:3d}% ", end='', flush=True)

# ---------------- readable password generator (same as before) ----------------
SIMPLE_SYLLABLES = [
    "ba","be","bi","bo","bu","ca","ce","ci","co","cu","da","de","di","do","du",
    "fa","fe","fi","fo","fu","la","le","li","lo","lu","ma","me","mi","mo","mu",
    "na","ne","ni","no","nu","ra","re","ri","ro","ru","sa","se","si","so","su",
    "ta","te","ti","to","tu",
]
def gen_readable_password(length:int=12, level:int=2) -> str:
    if level >= 4:
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return ''.join(choice(alphabet) for _ in range(length))
    if level == 1:
        pw = ''
        while len(pw) < length:
            if randbelow(100) < 60:
                pw += choice(SIMPLE_SYLLABLES)
            else:
                pw += choice('aeiou')
        return pw[:length]
    if level == 2:
        pw = ''
        while len(pw) < length:
            pw += choice(SIMPLE_SYLLABLES)
            if randbelow(100) < 30:
                pw += str(randbelow(10))
        return pw[:length]
    if level == 3:
        pw = ''
        symbols = "!@#$%&*?"
        while len(pw) < length:
            chunk = choice(SIMPLE_SYLLABLES)
            if randbelow(100) < 40:
                chunk = chunk.capitalize()
            pw += chunk
            if randbelow(100) < 35:
                pw += str(randbelow(10))
            if randbelow(100) < 20:
                pw += choice(symbols)
        return pw[:length]

# ---------------- interactive / CLI ----------------
MENU = """
1) Зашифровать файл
2) Расшифровать файл
3) Сгенерировать читаемые пароли
4) Сгенерировать и сохранить ключ
5) Загрузить ключ из файла
0) Выход
"""

def prompt_key_interactive() -> bytes:
    print("1) Ввести пароль (KDF)")
    print("2) Ввести base64 ключ")
    print("3) Сгенерировать случайный ключ")
    c = input("Выбор (1/2/3): ").strip()
    if c == '1':
        pwd = getpass("Пароль: ")
        pwd2 = getpass("Повтор: ")
        if pwd != pwd2:
            print("Не совпадает.")
            return prompt_key_interactive()
        salt = token_bytes(16)
        key = derive_key_from_password(pwd, salt)
        print("Salt (base64):", urlsafe_b64encode(salt).decode())
        return key
    if c == '2':
        b64 = input("Base64 ключ: ").strip()
        try:
            key = urlsafe_b64decode(b64)
            if len(key) != 32:
                print("Должен быть 32 байта.")
                return prompt_key_interactive()
            return key
        except Exception as e:
            print("Ошибка:", e)
            return prompt_key_interactive()
    return generate_key()

def interactive():
    current_key = None
    while True:
        print(Fore.GREEN + '''
   ──╔╗───╔═╗───────────╔╗────
    ╔╝║╔═╗║╬║╔══╗╔═╗╔═╗╔╝║
    ║╬║║╬║╠╗║║║║║║╬║║╬║║╬║
    ╚═╝╚═╝╚═╝╚╩╩╝╚═╝╚═╝╚═╝ ☭
    AES Stream Tool V1.0.0
   ───────────────────────────''')
        print(Fore.RED + MENU)
        cmd = input("Введите номер: ").strip()
        if cmd == '0':
            return
        if cmd == '1':
            inp = input("Входной файл: ").strip()
            out = input("Выход (зашифрованный): ").strip()
            try:
                chunk = int(input(f"Размер чанка в байтах (Enter для {DEFAULT_CHUNK}): ") or DEFAULT_CHUNK)
            except:
                chunk = DEFAULT_CHUNK
            if current_key is None:
                current_key = prompt_key_interactive()
            try:
                encrypt_stream(inp, out, current_key, chunk)
            except Exception as e:
                print("\nОшибка шифрования:", e)
        elif cmd == '2':
            inp = input("Зашифрованный файл: ").strip()
            out = input("Выход (расшифрованный): ").strip()
            if current_key is None:
                current_key = prompt_key_interactive()
            try:
                decrypt_stream(inp, out, current_key)
            except Exception as e:
                print("\nОшибка расшифровки:", e)
        elif cmd == '3':
            try:
                cnt = int(input("Количество: ").strip())
                length = int(input("Длина(примерно): ").strip())
                level = int(input("Уровень 1-4: ").strip())
            except:
                print("Неверный ввод.")
                continue
            for i in range(cnt):
                print(gen_readable_password(length, level))
        elif cmd == '4':
            path = input("Куда сохранить ключ: ").strip()
            k = generate_key()
            save_key_to_file(k, path)
            print("Saved. Base64:", urlsafe_b64encode(k).decode())
        elif cmd == '5':
            path = input("Путь к ключу: ").strip()
            try:
                k = load_key_from_file(path)
                if len(k) != 32:
                    print("Неверный ключ.")
                    continue
                current_key = k
                print("Ключ загружен.")
            except Exception as e:
                print("Ошибка:", e)
        else:
            print("Неизвестно.")

def main_cli():
    p = argparse.ArgumentParser(description="AES-256 GCM streaming encrypt/decrypt")
    p.add_argument('--encrypt', nargs=2, metavar=('IN','OUT'))
    p.add_argument('--decrypt', nargs=2, metavar=('IN','OUT'))
    p.add_argument('--keyfile', '-k')
    p.add_argument('--chunk', type=int, default=DEFAULT_CHUNK)
    p.add_argument('--gen-pass', nargs=3, metavar=('COUNT','LENGTH','LEVEL'))
    args = p.parse_args()

    key = None
    if args.keyfile:
        key = load_key_from_file(args.keyfile)
        if len(key) != 32:
            print("Ключ в файле должен быть 32 байта.")
            sys.exit(1)

    if args.gen_pass:
        cnt = int(args.gen_pass[0]); length = int(args.gen_pass[1]); level = int(args.gen_pass[2])
        for _ in range(cnt):
            print(gen_readable_password(length, level))
        sys.exit(0)

    if args.encrypt:
        if key is None:
            print("Укажите --keyfile или используйте интерактивный режим.")
            sys.exit(1)
        encrypt_stream(args.encrypt[0], args.encrypt[1], key, args.chunk)
        sys.exit(0)
    if args.decrypt:
        if key is None:
            print("Укажите --keyfile или используйте интерактивный режим.")
            sys.exit(1)
        decrypt_stream(args.decrypt[0], args.decrypt[1], key)
        sys.exit(0)

    interactive()

if __name__ == '__main__':
    try:
        main_cli()
    except KeyboardInterrupt:
        print("\nПрервано.")
        sys.exit(1)
