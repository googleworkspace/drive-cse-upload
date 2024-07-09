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

"""CSE Uploader. - xxx."""

import hashlib
import io
import mimetypes
import os
import pathlib
from typing import Any
from drive_cse_upload import _cse_crypter
from drive_cse_upload import _cse_drive_client
from drive_cse_upload import _cse_idp_client
from drive_cse_upload import _cse_kacls_client
from drive_cse_upload import _cse_util


class CseUploader(object):
  """Uploader of CSE files to Drive."""

  def __init__(
      self,
      sa_key_file: str,
      client_secret_file: str,
      saved_creds_file: str,
      validate: bool | None = True,
  ):
    """Constructor.

    Note: Arguments `sa_key_file`, `client_secret_file`, and `saved_creds_file`
    denote files containing sensitive information that should be protected.
    Users must ensure that the files passed-in / created here are not readable
    by anyone but their owner.

    Args:
        sa_key_file: Service-Account Private Key File path; callers must
          download the file from the Google Cloud Console and store it to this
          path.
        client_secret_file: Client Secret File path for the configured IDP OAuth
          Client-Id; callers must download the file from their IDP and store it
          to this path.
        saved_creds_file: Where to store the IDP Oauth credentials, created by
          this package.
        validate: If True (or omitted), validate every uploaded file by
          downloading and decrypting it. If validation of an uploaded file
          fails, delete it.
    """
    self._sa_key_file = os.path.abspath(sa_key_file)
    self._idp = _cse_idp_client.CseIdpClient(
        os.path.abspath(client_secret_file), os.path.abspath(saved_creds_file)
    )
    self._validate = validate

  def upload(
      self,
      input_file: str,
      delegated_user_email: str,
      parent_id: str | None = None,
  ) -> dict[str, Any]:
    """Upload a single file from local-host as a CSE file in Drive.

    Args:
        input_file: Local input file to upload.
        delegated_user_email: Upload the file as this user in Drive.
        parent_id: If not None, upload the file as a child of this parent
          (folder or shared-drive) in Drive. If omitted or None, upload the file
          to the root MyDrive of `delegated_user_email`.

    Returns:
      The metadata of the newly uploaded file, as a dict.

    Raises:
      RuntimeError: The uploaded file validation failed.
    """

    crypter = _cse_crypter.CseCrypter()
    kacls = _cse_kacls_client.CseKaclsClient()
    driver = _cse_drive_client.CseDriveClient(self._sa_key_file)

    content_type = mimetypes.guess_type(input_file)[0]
    filename = pathlib.Path(input_file).name

    driver.set_delegated_user(delegated_user_email)

    cse_token = driver.generate_cse_token(parent_id)
    jwt = cse_token['jwt']
    file_id = cse_token['fileId']
    kacls_id = cse_token['currentKaclsId']
    jwt_payload = driver.get_jwt_payload(jwt)
    resource_name = jwt_payload['resource_name']
    kacls_url = jwt_payload['kacls_url']
    perimeter_id = jwt_payload.get('perimeter_id', '')

    authn = self._idp.get_authn_token()

    outp = io.BytesIO()
    input_plaintext_digest = None
    with open(input_file, 'rb') as inp:
      crypter.encrypt(inp, outp)
      if self._validate:
        inp.seek(0)
        input_plaintext_digest = hashlib.file_digest(
            inp, hashlib.sha256
        ).hexdigest()  # pytype: disable=wrong-arg-types
    key = crypter.get_key()
    wdek = kacls.privileged_wrap(
        _cse_util.b64encode(key), resource_name, authn, kacls_url, perimeter_id
    )
    resource_key_hash = kacls.resource_key_hash(key, resource_name)

    encryption_details = driver.new_encryption_details(
        kacls_id,
        _cse_util.b64urlencode(wdek.encode()),
        _cse_util.b64urlencode(resource_key_hash.encode()),
    )
    decryption_metadata = encryption_details['decryptionMetadata']

    file = driver.cse_upload(
        outp, file_id, filename, encryption_details, parent_id, content_type
    )
    outp.close()

    if self._validate:
      drive_id = file['id']
      metadata, content = driver.cse_download(drive_id)

      downloaded_encryption_details = metadata['clientEncryptionDetails']
      downloaded_decryption_metadata = downloaded_encryption_details[
          'decryptionMetadata'
      ]
      downloaded_jwt = downloaded_decryption_metadata['jwt']
      downloaded_wdek = _cse_util.b64urldecode(
          downloaded_decryption_metadata['wrappedKey']
      ).decode()
      downloaded_jwt_payload = driver.get_jwt_payload(downloaded_jwt)
      downloaded_resource_name = downloaded_jwt_payload['resource_name']
      downloaded_kacls_url = downloaded_jwt_payload['kacls_url']
      authn = self._idp.get_authn_token()
      downloaded_key = kacls.privileged_unwrap(
          downloaded_wdek,
          downloaded_resource_name,
          authn,
          downloaded_kacls_url,
      )

      outp = io.BytesIO()
      content.seek(0)
      crypter.decrypt(_cse_util.b64decode(downloaded_key), content, outp)
      outp.seek(0)
      downloaded_plaintext_digest = hashlib.file_digest(
          outp, hashlib.sha256
      ).hexdigest()
      content.close()
      outp.close()

      for k in list(downloaded_decryption_metadata.keys()):
        if k not in decryption_metadata:
          del downloaded_decryption_metadata[k]
      if downloaded_encryption_details != encryption_details:
        driver.delete(drive_id)
        raise RuntimeError('Uploaded file metadata validation failed')
      if downloaded_plaintext_digest != input_plaintext_digest:
        driver.delete(drive_id)
        raise RuntimeError('Uploaded file decryption failed')

    return file
