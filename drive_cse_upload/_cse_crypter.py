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

"""CSE Data Encrypter/Decrypter."""

import enum
from drive_cse_upload import _cse_keyset_util
import tink
from tink import aead


class CseCrypter(object):
  """CSE Data Encrypter/Decrypter."""

  SAFE_CHUNK_COUNT_LIMIT = 1 << 30
  AEAD_OVERHEAD = 28
  PLAINTEXT_CHUNK_SIZE = 2097152
  CIPHERTEXT_CHUNK_SIZE = PLAINTEXT_CHUNK_SIZE + AEAD_OVERHEAD
  MAGIC_HEADER = bytes([0x99, 0x5E, 0xCC, 0x5E])

  class OpType(enum.Enum):
    ENCRYPT = 1
    DECRYPT = 2

  def __init__(self):
    self._key = None
    self._aead: aead.Aead = None
    self._current_chunk_count = 0
    aead.register()

  def encrypt(self, plaintext, ciphertext):
    """Encrypt plaintext data.

    Args:
      plaintext: Data to encrypt; a readable buffered file-like object.
      ciphertext: Encrypted data; a writable buffered file-like object.

    Returns:
        None
    """
    key_template = aead.aead_key_templates.AES256_GCM_RAW
    keyset_handle = tink.new_keyset_handle(key_template)
    self._key = self._get_key_from_handle(keyset_handle)
    self._aead = keyset_handle.primitive(aead.Aead)
    self._current_chunk_count = 0

    ciphertext.write(self.MAGIC_HEADER)
    buf = bytearray(self.PLAINTEXT_CHUNK_SIZE)
    while True:
      n = plaintext.readinto(buf)
      data = self._prefix(buf, n)
      # pylint: disable=g-explicit-length-test
      if n < self.PLAINTEXT_CHUNK_SIZE or len(plaintext.peek(1)) == 0:
        ciphertext.write(
            self._update(data, self.OpType.ENCRYPT, is_last_chunk=True)
        )
        break
      ciphertext.write(
          self._update(data, self.OpType.ENCRYPT, is_last_chunk=False)
      )

  def decrypt(self, key, ciphertext, plaintext):
    """Decrypt ciphertext data.

    Args:
      key: Key used to encrypt the ciphertext.
      ciphertext: Data to decrypt; a readable buffered file-like object.
      plaintext: Decrypted data; a writable buffered file-like object.

    Returns:
        None
    """
    keyset_handle = _cse_keyset_util.create_keyset_handle_from_aes_gcm_key(key)
    self._aead = keyset_handle.primitive(aead.Aead)
    self._current_chunk_count = 0

    magic = ciphertext.read(len(self.MAGIC_HEADER))
    if len(magic) != len(self.MAGIC_HEADER) or magic != self.MAGIC_HEADER:
      raise ValueError('Bad input')
    buf = bytearray(self.CIPHERTEXT_CHUNK_SIZE)
    while True:
      n = ciphertext.readinto(buf)
      data = self._prefix(buf, n)
      # pylint: disable=g-explicit-length-test
      if n < self.CIPHERTEXT_CHUNK_SIZE or len(ciphertext.peek(1)) == 0:
        plaintext.write(
            self._update(data, self.OpType.DECRYPT, is_last_chunk=True)
        )
        break
      plaintext.write(
          self._update(data, self.OpType.DECRYPT, is_last_chunk=False)
      )

  def get_key(self):
    """Get the encryption key.

    Returns:
      The key used in last `encrypt` call.
    """
    return self._key

  def _update(self, data, optype, is_last_chunk):
    """Encrypt/Decrypt the next chunk."""
    if self._current_chunk_count + 1 > self.SAFE_CHUNK_COUNT_LIMIT:
      raise ValueError('Input too large')
    associated_data = self._get_associated_data(
        self._current_chunk_count, is_last_chunk
    )
    match optype:
      case self.OpType.ENCRYPT:
        chunk = self._aead.encrypt(data, associated_data)
      case self.OpType.DECRYPT:
        chunk = self._aead.decrypt(data, associated_data)
    self._current_chunk_count += 1
    return chunk

  def _get_key_from_handle(self, keyset_handle):
    keyset = keyset_handle._keyset  # pylint: disable=protected-access
    key = keyset.key[0]
    key_data = key.key_data
    return key_data.value

  def _prefix(self, buf, n):
    assert n <= len(buf)
    if n == len(buf):
      return bytes(buf)
    return bytes(buf[0:n])

  def _get_associated_data(self, chunk_index, is_last_chunk):
    data = bytearray(chunk_index.to_bytes(4, 'big'))
    if is_last_chunk:
      data.append(1)
    else:
      data.append(0)
    return bytes(data)
