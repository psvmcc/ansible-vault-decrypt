#!/usr/bin/env python3

from ansible.parsing.utils.yaml import from_yaml
from ansible.parsing.vault import VaultSecret

import argparse
import os
from getpass import getpass


parser = argparse.ArgumentParser(description="ansible-vault-decrypt", add_help=False)
parser.add_argument(
    "-h", "--help", action="help", help="show this help message and exit"
)
parser.add_argument(
    "-d",
    dest="debug",
    help="debug mode output",
    action=argparse.BooleanOptionalAction,
)
parser.add_argument(
    "--vault-password-file",
    dest="vault_password_file",
    help="vault password file",
    default=os.environ.get("ANSIBLE_VAULT_PASSWORD_FILE"),
)
parser.add_argument("encrypted_file", type=str, help="Path to file to decrypt")

args = parser.parse_args()


def dict_to_yaml(input_dict, indent=0):
    result = ""
    for key, value in input_dict.items():
        if isinstance(value, dict):
            result += " " * indent + f"{key}:\n"
            result += dict_to_yaml(value, indent + 2)
        else:
            result += " " * indent + f"{key}: {value}\n"
    return result


def read_file(file_path):
    try:
        if os.access(file_path, os.X_OK):
            result = os.popen(file_path).read()
            return result
        with open(file_path, "r") as file:
            file = file.read()
        return file
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        exit(1)


def main(vault_secret):
    if args.debug:
        print(":: [DEBUG] Vault password: %s" % vault_secret)
    data = read_file(args.encrypted_file)
    output = ""
    try:
        unencrypted = from_yaml(
            data, vault_secrets=[("default", VaultSecret(vault_secret.encode("utf-8")))]
        )
        output = dict_to_yaml(unencrypted)
    except Exception as e:
        print(":: [ERROR] Decryption failure...")
        if args.debug:
            print(e)
        exit(1)
    print(output)


def entry_point():
    if not args.vault_password_file:
        vault_secret = getpass()
    else:
        vault_secret = read_file(args.vault_password_file).replace("\n", "")
    try:
        main(vault_secret)
    except KeyboardInterrupt:
        print("Interrupted")
        exit(130)


if __name__ == "__main__":
    entry_point()
