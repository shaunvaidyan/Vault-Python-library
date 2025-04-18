from secrets.local_secrets import *
from secrets.local_secrets import get_local_secret
from secrets.local_secrets import save_secret
from secrets.local_secrets import save_secrets

from secrets.vault import get_vault_secret


def get_secret(key, default=None, try_local=True, try_vault=True, env=None):
    """
    takes key & returns data saved from json_xor_create

    :param key: key for secret lookup
    :param default: default return value if the secret does not exist, defaults to None
    :param try_local: Try local secret first
    :param try_vault: Try vault secret
    """

    result = default

    if try_local and result == default:
        result = get_local_secret(key, default)
    if try_vault and result == default:
        result = get_vault_secret(key, default, env)

    return result


def get_secrets(secret_keys, default=None):
    """
    Takes list of secret keys, returns dict of keys to secrets
    optional default value is in place if secret does not exist.

    :param secret_keys: list of secret keys
    :param default: optional value for missing secrets
    :return:
    """
    output = {}
    for secret_key in secret_keys:
        output[secret_key] = get_secret(secret_key, default=default)
    return output
