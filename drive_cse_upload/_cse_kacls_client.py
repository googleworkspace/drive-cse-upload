# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Key ACLS Service (KACLS) API."""

import hashlib
import hmac
from drive_cse_upload import _cse_util
import requests


class CseKaclsClient(object):
  """KACLS API Client."""

  PRIV_WRAP = '/privilegedwrap'
  PRIV_UNWRAP = '/privilegedunwrap'

  def __init__(self):
    pass

  def privileged_wrap(
      self, key, resource_name, authn, kacls_url, perimeter_id=''
  ):
    """Wrap a data encryption key by a KACLS.

    Args:
        key: The base64-encoded data encryption key to wrap.
        resource_name: Name of the encrypted resource (Drive document).
        authn: An authentication token for the calling user.
        kacls_url: Base URL of the KACLS to use.
        perimeter_id: Optional perimeter id.

    Returns:
        The base64-encoded wrapped key computed by the KACLS.

    Raises:
      RuntimeError: An error occurred while calling the KACLS.
    """
    wrap_url = kacls_url + self.PRIV_WRAP
    request = {
        'key': key,
        'resource_name': resource_name,
        'perimeter_id': perimeter_id,
        'authentication': authn,
        'reason': 'import',
    }
    r = requests.post(wrap_url, json=request)
    if r.status_code != requests.codes.ok:
      raise RuntimeError('Wrap failed: ' + r.text)
    response = r.json()
    return response['wrapped_key']

  def privileged_unwrap(self, wrapped_key, resource_name, authn, kacls_url):
    """Unwrap a data encryption key by a KACLS.

    Args:
        wrapped_key: The base64-encoded wrapped key to unwrap.
        resource_name: Name of the encrypted resource (Drive document).
        authn: An authentication token for the calling user.
        kacls_url: Base URL of the KACLS to use.

    Returns:
        The base64-encoded unwrapped key computed by the KACLS.

    Raises:
      RuntimeError: An error occurred while calling the KACLS.
    """
    unwrap_url = kacls_url + self.PRIV_UNWRAP
    request = {
        'wrapped_key': wrapped_key,
        'resource_name': resource_name,
        'authentication': authn,
        'reason': 'import',
    }
    r = requests.post(unwrap_url, json=request)
    if r.status_code != requests.codes.ok:
      raise RuntimeError('Unwrap failed: ' + r.text)
    response = r.json()
    return response['key']

  def resource_key_hash(self, key, resource_name, perimeter_id=''):
    """Compute resource-key-hash.

    Args:
        key: The data encryption key.
        resource_name: Name of the encrypted resource (Drive document).
        perimeter_id: Optional perimeter id.

    Returns:
        A locally-computed base64-encoded resource_key_hash.
    """
    data = f'ResourceKeyDigest:{resource_name}:{perimeter_id}'.encode()
    digest = hmac.digest(key, data, hashlib.sha256)
    return _cse_util.b64encode(digest)
