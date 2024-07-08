# Drive CSE Upload

A Python library for uploading a file from local-host to Google Drive as a
Client Side Encrypted (CSE) document.

See https://support.google.com/a/answer/10741897

## Software Dependencies

### Python

-   Python 3.10.7 or greater

### Tink Cryptographic Library

-   https://developers.google.com/tink

```shell
pip3 install tink==1.10.0
```

### Google Client Library

-   https://developers.google.com/drive/api/quickstart/python

```shell
pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib
```

## Project Prerequisites

### Google Cloud

-   Have a [Cloud](https://console.cloud.google.com/) project
-   Have Google Drive API
    [enabled](https://developers.google.com/workspace/guides/view-turn-off-apis)
    for the project
-   Have a user with an admin rights in that project
-   Have a
    [service-account](https://developers.google.com/identity/protocols/oauth2#serviceaccount)
    configured for the project
-   Have the service-account provisioned for
    [Domain Wide Delegation](https://support.google.com/a/answer/162106)
-   Store the Service Account Private Key File downloaded during the account
    creation

    Note: The file is only downloaded during creation; you cannot re-download it

### Identity Provider (IDP)

-   Have an OAuth Client ID for Desktop
-   Download and store the Client Secret File for the configured OAuth Client Id

### Google Admin Console

-   Have [CSE](https://support.google.com/a/answer/14309952) configured for the
    domain
-   Have an IDP [configured](https://support.google.com/a/answer/10743588) for
    the domain
-   Have a
    [KACLS](https://developers.google.com/workspace/cse/guides/configure-service)
    configured for the domain

### Key ACL Service (KACLS)

-   The KACLS must support the `/privilegedwrap`, `/privilegedunwrap`, and
    `/digest` endpoints
-   Have the KACLS configured for the domain allow `/privilegedwrap` and
    `/privilegedunwrap` by the admin user
-   Have the KACLS configured for the domain allow `/digest` by Google
-   See https://developers.google.com/workspace/cse/reference

## Running the Example

-   Set these parameters to match your setup

    -   `SA_KEY_FILE`: The Service Account Private Key File
    -   `CLIENT_SECRET_FILE`: The OAuth Client Secret File
    -   `SAVED_CREDS_FILE`: Where to store the IDP Oauth credentials
    -   `AS_USER`: Upload the file as this user (an email-address)
    -   `INPUT_FILE` The file to upload
    -   `PARENT_ID` The parent folder/shared-drive for the uploaded file
        (optional)

    Note: The first three files listed above contain sensitive information that
    should be protected. Users must ensure that the files passed-in / created
    are not readable by anyone but their owner.

```shell
$ python example.py \
  --sa-key-file "${SA_KEY_FILE}" \
  --client-secret-file "${CLIENT_SECRET_FILE}" \
  --saved-creds-file "${SAVED_CREDS_FILE}" \
  --as-user "${AS_USER}" \
  "${INPUT_FILE}"
```

This will upload and validate the file `${INPUT_FILE}` to `${AS_USER}`'s root
MyDrive.

```shell
$ python example.py \
  --sa-key-file "${SA_KEY_FILE}" \
  --client-secret-file "${CLIENT_SECRET_FILE}" \
  --saved-creds-file "${SAVED_CREDS_FILE}" \
  --as-user "${AS_USER}" \
  --parent-id "${PARENT_ID}" \
  "${INPUT_FILE}"
```

This will upload and validate the file `${INPUT_FILE}` as a child of the folder
or shared-drive designated by `${PARENT_ID}`.

As part of the upload process, you'll be prompted to open a browser window with
a URL for authenticating with the IDP. Enter the admin user credentials there to
continue.

When done, the code will print the name and the id of the newly uploaded file.
You can see the file in the Drive web client. To ensure that the file is
uploaded correctly, now try the "Download and decrypt" action. This should
download the decrypted file to your local host.
