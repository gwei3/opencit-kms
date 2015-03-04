#!/bin/sh

# KMS install script
# Outline:
# 1. look for ~/kms.env and source it if it's there
# 2. source the "functions.sh" file:  mtwilson-linux-util-3.0-SNAPSHOT.sh
# 3. determine if we are installing as root or non-root user; set paths
# 4. detect java
# 5. if java not installed, and we have it bundled, install it
# 6. unzip kms archive kms-zip-0.1-SNAPSHOT.zip into /opt/kms, overwrite if any files already exist
# 7. link /usr/local/bin/kms -> /opt/kms/bin/kms, if not already there
# 8. add kms to startup services
# 9. look for KMS_PASSWORD environment variable; if not present print help message and exit:
#    KMS requires a master password
#    to generate a password run "export KMS_PASSWORD=$(kms generate-password) && echo KMS_PASSWORD=$KMS_PASSWORD"
#    you must store this password in a safe place
#    losing the master password will result in data loss
# 10. kms setup
# 11. kms start

#####

# default settings
KMS_HOME=${KMS_HOME:-/opt/kms}
KMS_LAYOUT=linux

# environment file
if [ -f kms.env ]; then
  echo "Loading environment variables from $(pwd)/kms.env"
  . kms.env
elif [ -f ~/kms.env ]; then
  echo "Loading environment variables from $(cd ~ && pwd)/kms.env"
  . ~/kms.env
else
  echo "No environment file"
fi

# functions script (mtwilson-linux-util-3.0-SNAPSHOT.sh) is required
# we use the following functions:
# java_detect java_ready_report 
# echo_failure echo_warning
# register_startup_script
UTIL_SCRIPT_FILE=`ls -1 mtwilson-linux-util-*.sh | head -n 1`
if [ -f "$UTIL_SCRIPT_FILE" ]; then
  . $UTIL_SCRIPT_FILE
fi


# determine if we are installing as root or non-root
if [ "$(whoami)" == "root" ]; then
  # create a kms user if there isn't already one created
  KMS_USERNAME=${KMS_USERNAME:-kms}
  if ! getent passwd $KMS_USERNAME 2>&1 >/dev/null; then
    useradd --comment "Mt Wilson KMS" --home $KMS_HOME --system --shell /bin/bash $KMS_USERNAME
  fi
else
  # already running as kms user
  KMS_USERNAME=$(whoami)
  echo_warning "Running as $KMS_USERNAME; if installation fails try again as root"
  if [ ! -w "$KMS_HOME" ] && [ ! -w $(dirname $KMS_HOME) ]; then
    export KMS_HOME=$(cd ~ && pwd)
  fi
fi

# define application directory layout
if [ "$KMS_LAYOUT" == "linux" ]; then
  export KMS_CONFIGURATION=${KMS_CONFIGURATION:-/etc/kms}
  export KMS_REPOSITORY=${KMS_REPOSITORY:-/var/opt/kms}
  export KMS_LOGS=${KMS_LOGS:-/var/log/kms}
elif [ "$KMS_LAYOUT" == "home" ]; then
  export KMS_CONFIGURATION=${KMS_CONFIGURATION:-$KMS_HOME/configuration}
  export KMS_REPOSITORY=${KMS_REPOSITORY:-$KMS_HOME/repository}
  export KMS_LOGS=${KMS_LOGS:-$KMS_HOME/logs}
fi
export KMS_ENV=$KMS_CONFIGURATION/env

# create application directories
for directory in $KMS_HOME $KMS_CONFIGURATION $KMS_ENV $KMS_REPOSITORY $KMS_LOGS; do
  mkdir -p $directory
  chown -R $KMS_USERNAME:$KMS_USERNAME $directory
  chmod 700 $directory
done


# store directory layout in env file
echo "# $(date)" > $KMS_ENV/kms-layout
echo "export KMS_HOME=$KMS_HOME" >> $KMS_ENV/kms-layout
echo "export KMS_CONFIGURATION=$KMS_CONFIGURATION" >> $KMS_ENV/kms-layout
echo "export KMS_REPOSITORY=$KMS_REPOSITORY" >> $KMS_ENV/kms-layout
echo "export KMS_LOGS=$KMS_LOGS" >> $KMS_ENV/kms-layout
echo "export KMS_ENV=$KMS_ENV" >> $KMS_ENV/kms-layout


# kms requires java 1.7 or later
# detect or install java (jdk-1.7.0_51-linux-x64.tar.gz)
JAVA_REQUIRED_VERSION=${JAVA_REQUIRED_VERSION:-1.7}
java_detect
if ! java_ready; then
  # java not installed, check if we have the bundle
  JAVA_INSTALL_REQ_BUNDLE=`ls -1 java-*.bin 2>/dev/null | head -n 1`
  if [ -n "$JAVA_INSTALL_REQ_BUNDLE" ]; then
    chmod +x $JAVA_INSTALL_REQ_BUNDLE
    ./$JAVA_INSTALL_REQ_BUNDLE
    java_detect
  fi
fi
if ! java_ready_report; then
  echo_failure "Java $JAVA_REQUIRED_VERSION not found"
  exit 1
fi

# make sure unzip is installed
KMS_YUM_PACKAGES="zip unzip"
KMS_APT_PACKAGES="zip unzip"
KMS_YAST_PACKAGES="zip unzip"
KMS_ZYPPER_PACKAGES="zip unzip"
auto_install "Installer requirements" "KMS"


# extract kms  (kms-zip-0.1-SNAPSHOT.zip)
echo "Extracting application..."
KMS_ZIPFILE=`ls -1 kms-*.zip 2>/dev/null | head -n 1`
unzip -oq $KMS_ZIPFILE -d $KMS_HOME
chown -R $KMS_USERNAME:$KMS_USERNAME $KMS_HOME
chmod 700 $KMS_HOME/bin/kms.sh

# copy utilities script file to application folder
cp $UTIL_SCRIPT_FILE $KMS_HOME/bin/functions.sh

# link /usr/local/bin/kms -> /opt/kms/bin/kms
EXISTING_KMS_COMMAND=`which kms`
if [ -z "$EXISTING_KMS_COMMAND" ]; then
  ln -s $KMS_HOME/bin/kms.sh /usr/local/bin/kms
fi


# register linux startup script
register_startup_script $KMS_HOME/bin/kms.sh kms

# the master password is required
if [ -z "$KMS_PASSWORD" ]; then
  echo_failure "Master password required in environment variable KMS_PASSWORD"
  echo 'To generate a new master password, run the following command:

  KMS_PASSWORD=$(kms generate-password) && echo KMS_PASSWORD=$KMS_PASSWORD

The master password must be stored in a safe place, and it must
be exported in the environment for all other kms commands to work.

LOSS OF MASTER PASSWORD WILL RESULT IN LOSS OF PROTECTED KEYS AND RELATED DATA

After you set KMS_PASSWORD, run the following command to complete installation:

  kms setup

'
  exit 1
fi

# setup the kms
kms setup

# start the server
kms start
