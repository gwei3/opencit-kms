#!/bin/sh

# KMS install script
# Outline:
# 1. source the "functions.sh" file:  mtwilson-linux-util-3.0-SNAPSHOT.sh
# 2. look for ~/kms.env and source it if it's there
# 3. detect java
# 4. if java not installed, and we have it bundled, install it
# 5. unzip kms archive kms-zip-0.1-SNAPSHOT.zip into /opt/kms, overwrite if any files already exist
# 6. link /usr/local/bin/kms -> /opt/kms/bin/kms, if not already there
# 7. look for KMS_PASSWORD environment variable; if not present print help message and exit:
#    KMS requires a master password
#    to generate a password run "export KMS_PASSWORD=$(kms generate-password) && echo KMS_PASSWORD=$KMS_PASSWORD"
#    you must store this password in a safe place
#    losing the master password will result in data loss
# 8. kms setup filesystem update-extensions-cache-file password-vault jetty jetty-tls-keystore envelope-key storage-key saml-certificates tpm-identity-certificates
# 9. kms start &
# 10. add kms to startup services

