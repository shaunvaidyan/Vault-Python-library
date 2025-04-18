import json
import os
from itertools import zip_longest


def xor_strings(s1, s2):
    """xors two strings, and reverses them"""
    return "".join([chr(ord(c1) ^ ord(c2)) for (c1, c2) in zip_longest(s1, s2, fillvalue=' ')])


def secret_path(key):
    """takes a key, generates for file, and creates directory if it doesnt exist"""
    home = os.path.expanduser("~")
    directory = os.path.join(home, '.infra')
    file_name = f'{key}.json'
    file_path = os.path.join(directory, file_name)
    if not os.path.exists(directory):
        os.mkdir(directory)
    return file_path


def save_secret(key, value):
    """takes a key, and value, dumps a json file with xord data with the key creates the file
    and returns the data """
    data = {key: value}
    json_encoded = json.dumps(data)
    xor_encoded = xor_strings(json_encoded, key)
    ords = [ord(char) for char in xor_encoded]
    file_path = secret_path(key)

    with open(file_path, 'w') as f:
        json.dump(ords, f)


def save_secrets(secrets):
    """
    takes a dict or a json dict of secrets and runs save_secret for each key,value

    :param secrets:  either a dict or a json dict
    :return: None
    """
    if type(secrets) == str:
        secrets = json.loads(secrets)
    for item in secrets.items():
        save_secret(*item)


def get_local_secret(key, default=None):
    result = default
    try:
        with open(secret_path(key), 'r') as f:
            encoded = json.load(f)
        xor_encoded = ''.join([chr(o) for o in encoded])
        json_encoded = xor_strings(xor_encoded, key)
        result = json.loads(json_encoded).get(key)
    except FileNotFoundError:
        pass
    return result
