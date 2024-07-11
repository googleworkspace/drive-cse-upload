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

import email.encoders
import email.generator
import email.mime.application
import email.mime.multipart
import email.mime.nonmultipart
import io
import json
import urllib.parse
import google
import google.oauth2.service_account
import google_auth_httplib2
from googleapiclient import http
from googleapiclient import model
import httplib2


class CseDriveClient(object):
  """Drive CSE API Client."""

  GOOGLEAPIS_URL = 'https://www.googleapis.com'

  DRIVE_FILES = 'drive/v3beta/files'
  FILES_METADATA_URL = f'{GOOGLEAPIS_URL}/{DRIVE_FILES}'
  FILES_UPLOAD_URL = f'{GOOGLEAPIS_URL}/upload/{DRIVE_FILES}'

  ENCRYPTED_MIME_TYPE_PREFIX = 'application/vnd.google-gsuite.encrypted'
  OCTET_STREAM = 'application/octet-stream'

  HEADERS = {
      'accept': 'application/json',
      'accept-encoding': 'gzip, deflate',
      'user-agent': '(gzip)',
  }
  PARAMS = {'alt': 'json', 'supportsTeamDrives': 'true'}

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
    self._model = model.JsonModel()
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
    if not self._delegated_user_email:
      raise ValueError('Delegated user email not set')
    creds = self._creds.with_subject(self._delegated_user_email)
    authorized_http = google_auth_httplib2.AuthorizedHttp(
        creds, http=self._http
    )

    params = self._new_params({'role': 'writer'})
    if parent_id:
      params['parentId'] = parent_id
    url = f'{self.FILES_METADATA_URL}/generateCseToken?{urllib.parse.urlencode(params)}'
    headers = self._new_headers({})

    request = http.HttpRequest(
        http=authorized_http,
        postproc=self._model.response,
        uri=url,
        method='GET',
        body=None,
        headers=headers,
        methodId='drive.files.generateCseToken',
    )

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
    if not self._delegated_user_email:
      raise ValueError('Delegated user email not set')
    creds = self._creds.with_subject(self._delegated_user_email)
    authorized_http = google_auth_httplib2.AuthorizedHttp(
        creds, http=self._http
    )

    params = self._new_params({'uploadType': 'multipart'})
    url = f'{self.FILES_UPLOAD_URL}?{urllib.parse.urlencode(params)}'

    file_metadata = {
        'id': file_id,
        'name': filename,
        'filename': filename,
        'mimeType': self._get_cse_mime_type(content_type),
        'clientEncryptionDetails': encryption_details,
    }
    if parent_id:
      file_metadata['parents'] = [parent_id]

    msg_root = self._build_media_upload_message(file_metadata, data_fp)
    body = self._get_message_body(msg_root)
    boundary = msg_root.get_boundary()

    content_type = f'multipart/related; boundary="{boundary}"'
    headers = self._new_headers({'content-type': content_type})

    request = http.HttpRequest(
        http=authorized_http,
        postproc=self._model.response,
        uri=url,
        method='POST',
        body=body,
        headers=headers,
        methodId='drive.files.insert',
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
    creds = self._creds.with_subject(self._delegated_user_email)
    authorized_http = google_auth_httplib2.AuthorizedHttp(
        creds, http=self._http
    )
    fields = [
        'id',
        'name',
        'mimeType',
        'clientEncryptionDetails/*',
    ]
    params = self._new_params({'fields': ','.join(fields)})
    url = (
        f'{self.FILES_METADATA_URL}/{file_id}?{urllib.parse.urlencode(params)}'
    )
    headers = self._new_headers({})

    request = http.HttpRequest(
        http=authorized_http,
        postproc=self._model.response,
        uri=url,
        method='GET',
        body=None,
        headers=headers,
        methodId='drive.files.get',
    )
    response = request.execute()
    metadata = response

    params = self._new_params({'alt': 'media'})
    url = (
        f'{self.FILES_METADATA_URL}/{file_id}?{urllib.parse.urlencode(params)}'
    )
    request = http.HttpRequest(
        http=authorized_http,
        postproc=None,
        uri=url,
        method='GET',
        body=None,
        headers=headers,
        methodId='drive.files.get',
    )
    buf = io.BytesIO()
    downloader = http.MediaIoBaseDownload(
        buf, request, chunksize=http.DEFAULT_CHUNK_SIZE
    )
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
    creds = self._creds.with_subject(self._delegated_user_email)
    authorized_http = google_auth_httplib2.AuthorizedHttp(
        creds, http=self._http
    )
    params = self._new_params({})
    url = (
        f'{self.FILES_METADATA_URL}/{file_id}?{urllib.parse.urlencode(params)}'
    )
    headers = self._new_headers({})

    request = http.HttpRequest(
        http=authorized_http,
        postproc=self._model.response,
        uri=url,
        method='DELETE',
        body=None,
        headers=headers,
        methodId='drive.files.delete',
    )
    response = request.execute()
    return response

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

  def _new_params(self, more_params):
    params = self.PARAMS.copy()
    params.update(more_params)
    return params

  def _new_headers(self, more_headers):
    headers = self.HEADERS.copy()
    headers.update(more_headers)
    return headers

  def _get_cse_mime_type(self, content_type=None):
    if not content_type:
      content_type = self.OCTET_STREAM
    return f'{self.ENCRYPTED_MIME_TYPE_PREFIX}; content="{content_type}"'

  def _build_media_upload_message(self, file_metadata, data_fp):
    """Build the media upload message."""
    # multipart/related upload
    msg_root = email.mime.multipart.MIMEMultipart('related')
    setattr(msg_root, '_write_headers', lambda self: None)

    # 1st part: metadata
    msg = email.mime.nonmultipart.MIMENonMultipart('application', 'json')
    msg.set_payload(json.dumps(file_metadata))
    msg_root.attach(msg)

    # 2nd part: data
    media_upload = http.MediaIoBaseUpload(
        fd=data_fp, mimetype=self.OCTET_STREAM
    )
    payload = media_upload.getbytes(0, media_upload.size())
    msg = email.mime.application.MIMEApplication(
        _data=payload, _encoder=email.encoders.encode_noop
    )
    msg['Content-Transfer-Encoding'] = 'binary'
    filename = file_metadata['filename']
    msg['Content-Disposition'] = (
        f'form-data; name="upload"; filename="{filename}"'
    )
    msg_root.attach(msg)

    return msg_root

  def _get_message_body(self, msg_root):
    # encode the body: note that we can't use `as_string`, because
    # it plays games with `From ` lines.
    fp = io.BytesIO()
    g = _BytesGenerator(fp, mangle_from_=False)
    g.flatten(msg_root, unixfrom=False)
    body = fp.getvalue()
    fp.close()
    return body


class _BytesGenerator(email.generator.BytesGenerator):
  _write_lines = email.generator.BytesGenerator.write
