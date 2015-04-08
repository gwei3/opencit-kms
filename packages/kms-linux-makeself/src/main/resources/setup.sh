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
# note the layout setting is used only by this script
# and it is not saved or used by the app script
export KMS_HOME=${KMS_HOME:-/opt/kms}
KMS_LAYOUT=${KMS_LAYOUT:-home}

# the env directory is not configurable; it is defined as KMS_HOME/env and the
# administrator may use a symlink if necessary to place it anywhere else
export KMS_ENV=$KMS_HOME/env

# load application environment variables if already defined
if [ -d $KMS_ENV ]; then
  KMS_ENV_FILES=$(ls -1 $KMS_ENV/*)
  for env_file in $KMS_ENV_FILES; do
    . $env_file
    env_file_exports=$(cat $env_file | grep -E '^[A-Z0-9_]+\s*=' | cut -d = -f 1)
    if [ -n "$env_file_exports" ]; then eval export $env_file_exports; fi
  done
fi

# load installer environment file, if present
if [ -f ~/kms.env ]; then
  echo "Loading environment variables from $(cd ~ && pwd)/kms.env"
  . ~/kms.env
  env_file_exports=$(cat ~/kms.env | grep -E '^[A-Z0-9_]+\s*=' | cut -d = -f 1)
  if [ -n "$env_file_exports" ]; then eval export $env_file_exports; fi
else
  echo "No environment file"
fi

# functions script (mtwilson-linux-util-3.0-SNAPSHOT.sh) is required
# we use the following functions:
# java_detect java_ready_report 
# echo_failure echo_warning
# register_startup_script
UTIL_SCRIPT_FILE=`ls -1 mtwilson-linux-util-*.sh | head -n 1`
if [ -n "$UTIL_SCRIPT_FILE" ] && [ -f "$UTIL_SCRIPT_FILE" ]; then
  . $UTIL_SCRIPT_FILE
fi


# determine if we are installing as root or non-root
if [ "$(whoami)" == "root" ]; then
  # create a kms user if there isn't already one created
  KMS_USERNAME=${KMS_USERNAME:-kms}
  if ! getent passwd $KMS_USERNAME 2>&1 >/dev/null; then
    useradd --comment "Mt Wilson KMS" --home $KMS_HOME --system --shell /bin/false $KMS_USERNAME
    usermod --lock $KMS_USERNAME
    # note: to assign a shell and allow login you can run "usermod --shell /bin/bash --unlock $KMS_USERNAME"
  fi
else
  # already running as kms user
  KMS_USERNAME=$(whoami)
  echo_warning "Running as $KMS_USERNAME; if installation fails try again as root"
  if [ ! -w "$KMS_HOME" ] && [ ! -w $(dirname $KMS_HOME) ]; then
    export KMS_HOME=$(cd ~ && pwd)
  fi
fi

# if an existing kms is already running, stop it while we install
if which kms; then
  kms stop
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
export KMS_BIN=${KMS_BIN:-$KMS_HOME/bin}
export KMS_JAVA=${KMS_JAVA:-$KMS_HOME/java}

# note that the env dir is not configurable; it is defined as "env" under home
export KMS_ENV=$KMS_HOME/env


kms_backup_configuration() {
  if [ -n "$KMS_CONFIGURATION" ] && [ -d "$KMS_CONFIGURATION" ]; then
    datestr=`date +%Y%m%d.%H%M`
    backupdir=/var/backup/kms.configuration.$datestr
    cp -r $KMS_CONFIGURATION $backupdir
  fi
}

kms_backup_repository() {
  if [ -n "$KMS_REPOSITORY" ] && [ -d "$KMS_REPOSITORY" ]; then
    datestr=`date +%Y%m%d.%H%M`
    backupdir=/var/backup/kms.repository.$datestr
    cp -r $KMS_REPOSITORY $backupdir
  fi
}

# backup current configuration and data, if they exist
kms_backup_configuration
kms_backup_repository

if [ -d $KMS_CONFIGURATION ]; then
  backup_conf_dir=$KMS_REPOSITORY/backup/configuration.$(date +"%Y%m%d.%H%M")
  mkdir -p $backup_conf_dir
  cp -R $KMS_CONFIGURATION/* $backup_conf_dir
fi

# create application directories (chown will be repeated near end of this script, after setup)
for directory in $KMS_HOME $KMS_CONFIGURATION $KMS_ENV $KMS_REPOSITORY $KMS_LOGS; do
  mkdir -p $directory
  chown -R $KMS_USERNAME:$KMS_USERNAME $directory
  chmod 700 $directory
done


# store directory layout in env file
echo "# $(date)" > $KMS_ENV/kms-layout
echo "export KMS_HOME=$KMS_HOME" >> $KMS_ENV/kms-layout
echo "export KMS_CONFIGURATION=$KMS_CONFIGURATION" >> $KMS_ENV/kms-layout
echo "export KMS_JAVA=$KMS_JAVA" >> $KMS_ENV/kms-layout
echo "export KMS_BIN=$KMS_BIN" >> $KMS_ENV/kms-layout
echo "export KMS_REPOSITORY=$KMS_REPOSITORY" >> $KMS_ENV/kms-layout
echo "export KMS_LOGS=$KMS_LOGS" >> $KMS_ENV/kms-layout

# store kms username in env file
echo "# $(date)" > $KMS_ENV/kms-username
echo "export KMS_USERNAME=$KMS_USERNAME" >> $KMS_ENV/kms-username

# store log level in env file, if it's set
if [ -n "$KMS_LOG_LEVEL" ]; then
  echo "# $(date)" > $KMS_ENV/kms-logging
  echo "export KMS_LOG_LEVEL=$KMS_LOG_LEVEL" >> $KMS_ENV/kms-logging
fi

# store the auto-exported environment variables in env file
# to make them available after the script uses sudo to switch users;
# we delete that file later
echo "# $(date)" > $KMS_ENV/kms-setup
for env_file_var_name in $env_file_exports
do
  eval env_file_var_value="\$$env_file_var_name"
  echo "export $env_file_var_name=$env_file_var_value" >> $KMS_ENV/kms-setup
done

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

# make sure unzip and authbind are installed
KMS_YUM_PACKAGES="zip unzip authbind"
KMS_APT_PACKAGES="zip unzip authbind"
KMS_YAST_PACKAGES="zip unzip authbind"
KMS_ZYPPER_PACKAGES="zip unzip authbind"
auto_install "Installer requirements" "KMS"

# setup authbind to allow non-root kms to listen on ports 80 and 443
if [ -n "$KMS_USERNAME" ] && [ "$KMS_USERNAME" != "root" ] && [ -d /etc/authbind/byport ]; then
  touch /etc/authbind/byport/80 /etc/authbind/byport/443
  chmod 500 /etc/authbind/byport/80 /etc/authbind/byport/443
  chown $KMS_USERNAME /etc/authbind/byport/80 /etc/authbind/byport/443
fi

# delete existing java files, to prevent a situation where the installer copies
# a newer file but the older file is also there
if [ -d $KMS_HOME/java ]; then
  rm $KMS_HOME/java/*.jar
fi

# extract kms  (kms-zip-0.1-SNAPSHOT.zip)
echo "Extracting application..."
KMS_ZIPFILE=`ls -1 kms-*.zip 2>/dev/null | head -n 1`
unzip -oq $KMS_ZIPFILE -d $KMS_HOME

# copy utilities script file to application folder
cp $UTIL_SCRIPT_FILE $KMS_HOME/bin/functions.sh

# set permissions
chown -R $KMS_USERNAME:$KMS_USERNAME $KMS_HOME
chmod 755 $KMS_HOME/bin/*

# link /usr/local/bin/kms -> /opt/kms/bin/kms
EXISTING_KMS_COMMAND=`which kms`
if [ -z "$EXISTING_KMS_COMMAND" ]; then
  ln -s $KMS_HOME/bin/kms.sh /usr/local/bin/kms
fi


# register linux startup script
register_startup_script $KMS_HOME/bin/kms.sh kms
# setup the kms, unless the NOSETUP variable is defined
if [ -z "$KMS_NOSETUP" ]; then

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

  kms config mtwilson.extensions.fileIncludeFilter.contains "${MTWILSON_EXTENSIONS_FILEINCLUDEFILTER_CONTAINS:-mtwilson,kms}" >/dev/null
  kms setup
fi

# delete the temporary setup environment variables file
rm -f $KMS_ENV/kms-setup

# ensure the kms owns all the content created during setup
for directory in $KMS_HOME $KMS_CONFIGURATION $KMS_JAVA $KMS_BIN $KMS_ENV $KMS_REPOSITORY $KMS_LOGS; do
  chown -R $KMS_USERNAME:$KMS_USERNAME $directory
done

# start the server, unless the NOSETUP variable is defined
if [ -z "$KMS_NOSETUP" ]; then kms start; fi
