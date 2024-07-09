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

"""CSE Tink Keyset utils."""

# copybara:strip_begin
from tink import secret_key_access
from google3.third_party.tink.integration.python.cse import keyset_converter


def create_keyset_handle_from_aes_gcm_key(key):
  return keyset_converter.create_keyset_handle_from_aes_gcm_key(
      key, secret_key_access.TOKEN
  )


# copybara:strip_end_and_replace_begin
# import tink
# from tink import aead
# from tink import cleartext_keyset_handle
# from tink.proto import tink_pb2
#
# def create_keyset_handle_from_aes_gcm_key(key):
#   aes_gcm_key_type_url = aead.aead_key_templates.AES256_GCM_RAW.type_url
#   key_id = 1;
#   keyset = tink_pb2.Keyset()
#   keyset.primary_key_id = key_id
#   pkey = keyset.key.add()
#   pkey.status = tink_pb2.KeyStatusType.ENABLED
#   pkey.output_prefix_type = tink_pb2.OutputPrefixType.RAW
#   pkey.key_id = key_id
#   pkey.key_data.type_url = aes_gcm_key_type_url
#   pkey.key_data.value = key
#   pkey.key_data.key_material_type = tink_pb2.KeyData.KeyMaterialType.SYMMETRIC
#   return cleartext_keyset_handle.from_keyset(keyset)
# copybara:replace_end
