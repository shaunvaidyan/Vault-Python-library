import traceback
import warnings
import hvac
import urllib3
from functools import partial
from cached_property import cached_property
from .local_secrets import get_local_secret


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # fix CA certs in all locations.

URLS = ['https://VAULT-URL-HERE.com']


def vault_client_generator(urls=None, env=None, auth=None, *args, **kwargs):
    if not urls:
        urls = URLS
    for url in urls:
        vault_client = VaultClient(url, environment=env, auth=auth, *args, **kwargs)
        yield vault_client


def get_vault_secret(key, default=None, env=None):
    for vault_client in vault_client_generator(env=env):
        try:
            secret = vault_client.get_secret(key)
            if secret:
                return secret
        except Exception as e:
            # todo: do failover testing, and only catch specific exceptions
            message = f'Exception trying to get secret {key} from {vault_client.url}\n{e}'
            message += '\n'.join(traceback.format_stack())

            warnings.warn(message)
    return default


def create_approle(user, ip_addresses=None, policies=None, auth=None, urls=None):
    """
    Creates an approle with associated
    :param user: Name of the user
    :param ip_addresses: List of IP Addresses that are allowed to use the approle
    :param policies: List of policies to apply to the approle
    :param auth: Full output of 'vault_approle'
    :param urls: List of addresses of vault, if specified
    """
    for vault_client in vault_client_generator(urls=urls, auth=auth):
        try:
            approle = vault_client.create_approle(user, policies=['dev'], ip_addr=ip_addresses)
            if approle:
                return approle
        except Exception as e:
            message = f'Exception trying to create approle on {vault_client.url}\n{e}'
            message += '\n'.join(traceback.format_stack())
            warnings.warn(message)


class VaultClient:
    default_mount_point = 'homelab'
    default_environment = 'development'
    default_auth_key = 'vault_approle'
    special_key = 'vaidyan'

    def __init__(self, url, auth_key=None, environment=None, auth=None):
        self.url = url
        self._auth_key = auth_key
        self._environment = environment
        self._auth = auth

    @property
    def auth_key(self):
        return self._auth_key or self.default_auth_key

    @property
    def environment(self):
        return self._environment or self.local_secret_environment or self.default_environment

    @cached_property
    def local_secret_environment(self):
        environment = get_local_secret('environment')
        if 'prod' in environment.lower():
            return 'production'
        if 'dev' in environment.lower():
            return 'development'

    @cached_property
    def auth(self):
        return get_local_secret(self.auth_key)

    @cached_property
    def _list_secrets(self):
        mount_point = self.default_mount_point
        return partial(self.kv.list_secrets, mount_point=mount_point)

    @cached_property
    def client(self):
        hvac.api.secrets_engines.kv_v2.DEFAULT_MOUNT_POINT = self.default_mount_point
        if self._auth:
            auth = self._auth
        else:
            auth = self.auth.copy()
        auth_type = auth.pop('type')
        if auth_type == 'token':
            return hvac.Client(url=self.url, verify=False, token=auth['token'])
        elif auth_type == 'approle':
            client = hvac.Client(url=self.url, verify=False)
            client.auth.approle.login(**auth)
            return client
        return

    @property
    def kv(self):
        return self.client.secrets.kv.v2

    def read_secret_version(self, path, mount_point=None, *args, **kwargs):
        if not mount_point:
            mount_point = self.default_mount_point
        return self.kv.read_secret_version(path, mount_point=mount_point, *args, **kwargs)

    def _get_secret_if_it_exists(self, path, default=None):
        try:
            result = self.read_secret_version(path)

        except hvac.exceptions.InvalidPath:
            result = default
        return result

    def _parse_secret(self, secret):
        """returns the latest secret data, if the data only has supplied key"""

        data = secret.get('data', {}).get('data', {})
        if len(data) == 1 and self.special_key in data:
            data = data[self.special_key]
        return data

    def _get_and_parse_secret(self, path, default=None):
        secret = self._get_secret_if_it_exists(path, default)
        if secret and secret != default:
            secret = self._parse_secret(secret)
        if secret:
            return secret
        return default

    def get_secret(self, key, default=None):
        path = f"{self.environment}/{key}"

        result = self._get_and_parse_secret(path, default)
        if not result or result == default:
            result = self._get_and_parse_secret(key, default)
        if not result or result == default:
            result = default

        return result

    def walk_secrets(self, path=''):
        response = self._list_secrets(path)
        secrets = response['data']['keys']
        while secrets:
            secret = secrets.pop()
            if path:
                secret = f'{path}{secret}'
            if secret.endswith('/'):
                secrets += list(self.walk_secrets(secret))
            else:
                yield secret

    def delete_secret(self, path):
        return self.kv.delete_metadata_and_all_versions(path=path, mount_point=self.default_mount_point)

    def save_secret(self, path, secret):
        if not isinstance(secret, dict):
            secret = {self.special_key: secret}
        return self.kv.create_or_update_secret(path=path, secret=secret, mount_point=self.default_mount_point)

    def secrets_generator(self, path=''):
        for secret_path in self.walk_secrets(path):
            yield secret_path, self._get_and_parse_secret(secret_path)

    def create_approle(self, user, policies=['developers'], ip_addr=[]):
        """
        :param user: Name of the user
        :param policies: List of policies to apply to the role
        :param ip_addr: List of IP addresses to lock the role to
        """
        data = {'role_name': user,
                'token_policies': policies,
                'secret_id_ttl': '0m',
                'token_num_uses': 0,
                'token_ttl': '0m',
                'token_max_ttl': '0m',
                'secret_id_num_uses': 0,
                }
        if ip_addr:
            data['token_bound_cidrs'] = ip_addr
            data['secret_id_bound_cidrs'] = []
            for ip in ip_addr:
                data['secret_id_bound_cidrs'].append(f"{ip}/32")

        self.client.auth.approle.create_or_update_approle(**data)
        role_id = self.get_role_id(user)
        secret_id = self.generate_secret_id(user)
        info = {'role_id': role_id, 'secret_id': secret_id, 'type': 'approle'}
        print(info)
        return info

    def generate_secret_id(self, user):
        data = {'role_name': user}
        response = self.client.auth.approle.generate_secret_id(**data)
        return response['data']['secret_id']

    def get_role_id(self, user):
        """
        :param user: Name of the user
        """
        return self.client.auth.approle.read_role_id(user)
