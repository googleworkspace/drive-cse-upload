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

import random
from drive_cse_upload import _cse_util
from google3.testing.pybase import googletest


class CseUtilTest(googletest.TestCase):

  def test_b64encode(self):
    data = b'i\x9f\xbb\xeb\xfc'
    self.assertEqual(_cse_util.b64encode(data), 'aZ+76/w=')

  def test_b64urlencode(self):
    data = b'i\x9f\xbb\xeb\xfc'
    self.assertEqual(_cse_util.b64urlencode(data), 'aZ-76_w=')

  def test_b64decode(self):
    data = 'aZ+76/w='
    self.assertEqual(_cse_util.b64decode(data), b'i\x9f\xbb\xeb\xfc')

  def test_b64urldecode(self):
    data = 'aZ-76_w='
    self.assertEqual(_cse_util.b64urldecode(data), b'i\x9f\xbb\xeb\xfc')

  def test_b64_roundtrip(self):
    data = random.randbytes(random.randint(2, 257))
    self.assertEqual(data, _cse_util.b64decode(_cse_util.b64encode(data)))

  def test_b64url_roundtrip(self):
    data = random.randbytes(random.randint(2, 257))
    self.assertEqual(data, _cse_util.b64urldecode(_cse_util.b64urlencode(data)))


if __name__ == '__main__':
  googletest.main()
