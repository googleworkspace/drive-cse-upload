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

"""Identity Provider (IDP) API."""

import datetime
import json
import os
import threading
from google.auth.exceptions import RefreshError
from google.auth.transport.requests import Request
from google.oauth2 import credentials
from google_auth_oauthlib.flow import InstalledAppFlow


class CseIdpClient(object):
  """Identity Provider (IDP) Client."""

  SCOPES = ['openid', 'email']

  def __init__(self, client_secret_file, saved_creds_file):
    """Constructor.

    Note: All the arguments denote files containing sensitive information that
    should be protected. Users must ensure that the files passed-in / created
    here are not readable by anyone but their owner.

    Args:
        client_secret_file: Client Secret File path for the configured IDP OAuth
          Client-Id; callers must download the file from their IDP and store it
          to this path.
        saved_creds_file: Where to store the IDP Oauth credentials, created by
          this module.
    """
    self._client_secret_file = client_secret_file
    self._saved_creds_file = saved_creds_file
    self._creds: credentials.Credentials = None
    self._lock = threading.Lock()

  def get_authn_token(self):
    """Get an OAuth id-token.

    Returns:
      An OAuth id-token for the calling user.
    """
    with self._lock:
      self._get_creds()
      return self._creds.id_token

  def _get_creds(self):
    """Get credentials."""

    # Google Python client library work-around for servers changing scopes
    os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = 'True'

    if not self._creds:
      self._creds = self._read_creds_from_file()

    if self._creds and self._creds.valid:
      return

    if self._creds:
      try:
        self._creds.refresh(Request())
        if self._creds.valid:
          return
      except RefreshError:
        pass

    flow = InstalledAppFlow.from_client_secrets_file(
        self._client_secret_file, scopes=self.SCOPES
    )
    self._creds = flow.run_local_server(open_browser=False, port=0)
    self._write_creds_to_file()

  def _read_creds_from_file(self):
    """Read credentials from file."""
    creds = None
    if os.path.exists(self._saved_creds_file):
      try:
        with open(self._saved_creds_file, 'r') as f:
          creds_json = json.load(f)
        creds = credentials.Credentials(
            token=creds_json.get('access_token'),
            refresh_token=creds_json.get('refresh_token'),
            id_token=creds_json.get('id_token'),
            token_uri=creds_json.get('token_uri'),
            client_id=creds_json.get('client_id'),
            client_secret=creds_json.get('client_secret'),
            scopes=creds_json.get('scopes'),
            expiry=datetime.datetime.fromtimestamp(
                creds_json.get('token_expiry')
            ),
        )
      except (IOError, TypeError, ValueError, KeyError):
        pass
    return creds

  def _write_creds_to_file(self):
    """Write credentials to file."""
    if self._creds:
      expiry = self._creds.expiry
      if not expiry:
        expiry = datetime.datetime.now()
      creds_json = {
          'access_token': self._creds.token,
          'refresh_token': self._creds.refresh_token,
          'id_token': self._creds.id_token,
          'token_uri': self._creds.token_uri,
          'client_id': self._creds.client_id,
          'client_secret': self._creds.client_secret,
          'scopes': self._creds.scopes,
          'token_expiry': expiry.timestamp(),
      }
      try:
        with open(self._saved_creds_file, 'w') as f:
          json.dump(creds_json, f)
      except (IOError, TypeError, ValueError, RecursionError):
        pass
