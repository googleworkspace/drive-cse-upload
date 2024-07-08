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

"""CSE Utilities."""

import base64


def b64encode(data: bytes) -> str:
  """B64 encode.

  Args:
      data: Bytes to encode.

  Returns:
      A base64-encoded string of the data bytes.
  """
  return base64.b64encode(data).decode()


def b64urlencode(data: bytes) -> str:
  """B64 URL encode.

  Args:
      data: Bytes to encode.

  Returns:
      A URL-base64-encoded string of the data bytes.
  """
  return base64.b64encode(data, altchars=b'-_').decode()


def b64decode(data: str) -> bytes:
  """B64 decode.

  Args:
      data: String to decode.

  Returns:
      A base64-decoded bytes of the data string.
  """
  return base64.b64decode(data)


def b64urldecode(data: str) -> bytes:
  """B64 URL decode.

  Args:
      data: String to decode.

  Returns:
      A URL-base64-decoded bytes of the data string.
  """
  return base64.b64decode(data, altchars=b'-_')
