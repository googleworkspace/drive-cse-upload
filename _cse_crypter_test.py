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

import io
import random
from drive_cse_upload import _cse_crypter
from google3.testing.pybase import googletest


class CseCrypterTest(googletest.TestCase):

  def test_encrypt_short(self):
    # single chunk
    data = b'Hello, CSE World!'
    self._do_test_encrypt(data)

  def test_encrypt_long(self):
    chunk_size = _cse_crypter.CseCrypter.PLAINTEXT_CHUNK_SIZE
    # at least 2 chunks
    length = random.randint(2 * chunk_size, 5 * chunk_size)
    data = random.randbytes(length)
    self._do_test_encrypt(data)

  def _do_test_encrypt(self, data):
    crypter = _cse_crypter.CseCrypter()
    plaintext = io.BytesIO(data)
    ciphertext = io.BytesIO()
    crypter.encrypt(plaintext, ciphertext)
    plaintext.seek(0)
    ciphertext.seek(0)
    plaintext2 = io.BytesIO()
    crypter.decrypt(crypter.get_key(), ciphertext, plaintext2)
    plaintext2.seek(0)
    self.assertEqual(plaintext2.read(), plaintext.read())


if __name__ == '__main__':
  googletest.main()
