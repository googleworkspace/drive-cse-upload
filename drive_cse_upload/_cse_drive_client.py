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

"""Drive CSE API."""

import io
import google
import google.oauth2.service_account
import google_auth_httplib2
from googleapiclient import discovery
from googleapiclient import http
import httplib2


class CseDriveClient(object):
  """Drive CSE API Client."""

  ENCRYPTED_MIME_TYPE_PREFIX = 'application/vnd.google-gsuite.encrypted'
  OCTET_STREAM = 'application/octet-stream'

  SCOPES = ['https://www.googleapis.com/auth/drive']

  def __init__(self, sa_key_file):
    """Constructor.

    Args:
        sa_key_file: Service-Account Key File path.
    """
    self._creds = (
        google.oauth2.service_account.Credentials.from_service_account_file(
            sa_key_file, scopes=self.SCOPES
        )
    )
    self._http = httplib2.Http()
    self._delegated_user_email = None

  def set_delegated_user(self, delegated_user_email):
    """Set the delegate user for future calls to Drive.

    Args:
        delegated_user_email: The delegated user. All subsequent calls to this
          CseDriveClient, until this method is called again, will be on behalf
          of this user. Must be called before making calls to Drive.
    """
    self._delegated_user_email = delegated_user_email

  def generate_cse_token(self, parent_id=None):
    """Generate a CSE Token.

    Args:
        parent_id: Generate a token for a file in this parent in Drive. If None,
          use the root MyDrive of `delegated_user_email`.

    Returns:
        A CSE Token, as a dict.
    """
    with self._service() as service:
      request = service.files().generateCseToken(parent=parent_id)
      response = request.execute()
      return response

  def cse_upload(
      self,
      data_fp,
      file_id,
      filename,
      encryption_details,
      parent_id,
      content_type,
  ):
    """Upload the given data as a new CSE file.

    Args:
      data_fp: The ciphertext data to upload; a readable file-like object.
      file_id: The Drive id of the file being uploaded.
      filename: The name of the file being uploaded.
      encryption_details: Encryption metadata for the file being uploaded.
      parent_id: The parent of the file being uploaded. If None, use the root
        MyDrive of `delegated_user_email`.
      content_type: The content-type of the file being uploaded.

    Returns:
      The metadata of the newly uploaded file, as a dict.
    """
    file_metadata = {
        'id': file_id,
        'name': filename,
        'filename': filename,
        'mimeType': self._get_cse_mime_type(content_type),
        'clientEncryptionDetails': encryption_details,
    }
    if parent_id:
      file_metadata['parents'] = [parent_id]
    media = http.MediaIoBaseUpload(fd=data_fp, mimetype=self.OCTET_STREAM)
    with self._service() as service:
      request = service.files().create(
          body=file_metadata, media_body=media, supportsAllDrives=True
      )
      response = request.execute()
      return response

  def cse_download(self, file_id):
    """Download the (encrypted) content and metadata of a CSE file.

    Args:
      file_id: The Drive id of the file to download.

    Returns:
      The metadata of the downloaded file, as a dict, and the file's content,
      as a BytesIO object. The caller must close() the object.
    """
    with self._service() as service:
      fields = 'id, name, mimeType, clientEncryptionDetails/*'
      request = service.files().get(
          fileId=file_id, fields=fields, supportsAllDrives=True
      )
      response = request.execute()
      metadata = response

      buf = io.BytesIO()
      request = service.files().get_media(fileId=file_id)
      downloader = http.MediaIoBaseDownload(buf, request)
      done = False
      while not done:
        _, done = downloader.next_chunk()
      return (metadata, buf)

  def delete(self, file_id):
    """Delete a file.

    Args:
      file_id: The Drive id of the file to delete.

    Returns:
      Empty dict.
    """
    with self._service() as service:
      request = service.files().delete(fileId=file_id, supportsTeamDrives=True)
      request.execute()
      return {}

  def get_jwt_payload(self, jwt):
    """Extract the payload from a JWT.

    Args:
      jwt: A JSON Web Token.

    Returns:
      The payload part of a given jwt, as a dict.
    """
    return google.auth.jwt.decode(token=jwt, verify=False)

  def new_encryption_details(self, kacls_id, wdek, resource_key_hash):
    """Create new encryption-details metadata for a CSE file.

    Args:
      kacls_id: The Drive ID of the KACLS to use.
      wdek: The wrapped data encryption key.
      resource_key_hash: A digest of the encryption key and the encrypted
        resource.

    Returns:
      Encryption-details metadata, as a dict.
    """
    decryption_metadata = {
        'wrappedKey': wdek,
        'kaclsId': kacls_id,
        'aes256GcmChunkSize': 'default',
        'keyFormat': 'tinkAesGcmKey',
        'encryptionResourceKeyHash': resource_key_hash,
    }
    return {
        'encryptionState': 'encrypted',
        'decryptionMetadata': decryption_metadata,
    }

  def _service(self):
    if not self._delegated_user_email:
      raise ValueError('Delegated user email not set')
    creds = self._creds.with_subject(self._delegated_user_email)
    authorized_http = google_auth_httplib2.AuthorizedHttp(
        creds, http=self._http
    )
    service = discovery.build('drive', 'v3', http=authorized_http())
    return service

  def _get_cse_mime_type(self, content_type=None):
    if not content_type:
      content_type = self.OCTET_STREAM
    return f'{self.ENCRYPTED_MIME_TYPE_PREFIX}; content="{content_type}"'
