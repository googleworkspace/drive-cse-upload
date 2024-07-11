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

from drive_cse_upload import _cse_kacls_client
from absl.testing import absltest


class CseKaclsClientTest(absltest.TestCase):

  def test_resource_key_hash(self):
    client = _cse_kacls_client.CseKaclsClient()
    key = b'data-encryption-key'
    resource_name = 'resource-name'
    digest = 'BzUyXkZ0424Ve8NtOB1CWgg5hVx60OAPf9SNbVPdtUo='
    self.assertEqual(client.resource_key_hash(key, resource_name), digest)


if __name__ == '__main__':
  absltest.main()
