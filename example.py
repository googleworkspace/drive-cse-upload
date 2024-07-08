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

"""Example for CSE Upload."""

import argparse
import pathlib
import sys
from drive_cse_upload import cse_uploader


def main():
  parser = argparse.ArgumentParser(
      prog='example', usage='%(prog)s [options...] <input-file>'
  )
  parser.add_argument(
      '--sa-key-file',
      dest='sa_key_file',
      required=True,
      help='service-account private key file [required]',
  )
  parser.add_argument(
      '--client-secret-file',
      dest='client_secret_file',
      required=True,
      help='oauth client secret file [required]',
  )
  parser.add_argument(
      '--saved-creds-file',
      dest='saved_creds_file',
      required=True,
      help='saved credentials file [required]',
  )
  parser.add_argument(
      '--as-user',
      dest='as_user',
      required=True,
      help='upload the file as this user [required]',
  )
  parser.add_argument(
      '--parent-id',
      dest='parent_id',
      help='parent folder/shared-drive for the uploaded file [None]',
  )
  parser.add_argument(
      '--validate',
      dest='validate',
      action=argparse.BooleanOptionalAction,
      default=True,
      help='validate the upload [True]',
  )
  parser.add_argument('input_file', metavar='input-file', help='file to upload')
  args = parser.parse_args()

  uploader = cse_uploader.CseUploader(
      args.sa_key_file,
      args.client_secret_file,
      args.saved_creds_file,
      args.validate,
  )
  filename = pathlib.Path(args.input_file).name
  try:
    file = uploader.upload(args.input_file, args.as_user, args.parent_id)
    drive_id = file['id']
    print(f'Uploaded {filename} as {drive_id}')
  except RuntimeError as e:
    print(f'File {filename} could not be uploaded: {e}')
    sys.exit(1)

if __name__ == '__main__':
  main()
