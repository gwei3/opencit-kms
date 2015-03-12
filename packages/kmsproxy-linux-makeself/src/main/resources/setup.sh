#!/bin/sh

# KMSPROXY install script
# Outline:
# 1. look for ~/kmsproxy.env and source it if it's there
# 2. source the "functions.sh" file:  mtwilson-linux-util-3.0-SNAPSHOT.sh
# 3. determine if we are installing as root or non-root user; set paths
# 4. detect java
# 5. if java not installed, and we have it bundled, install it
# 6. unzip kmsproxy archive kmsproxy-zip-0.1-SNAPSHOT.zip into /opt/kmsproxy, overwrite if any files already exist
# 7. link /usr/local/bin/kmsproxy -> /opt/kmsproxy/bin/kmsproxy, if not already there
# 8. add kmsproxy to startup services
# 9. look for KMSPROXY_PASSWORD environment variable; if not present print help message and exit:
#    KMSPROXY requires a master password
#    to generate a password run "export KMSPROXY_PASSWORD=$(kmsproxy generate-password) && echo KMSPROXY_PASSWORD=$KMSPROXY_PASSWORD"
#    you must store this password in a safe place
#    losing the master password will result in data loss
# 10. kmsproxy setup
# 11. kmsproxy start

#####

# default settings
KMSPROXY_HOME=${KMSPROXY_HOME:-/opt/kmsproxy}
KMSPROXY_LAYOUT=linux

# environment file
if [ -f kmsproxy.env ]; then
  echo "Loading environment variables from $(pwd)/kmsproxy.env"
  . kmsproxy.env
elif [ -f ~/kmsproxy.env ]; then
  echo "Loading environment variables from $(cd ~ && pwd)/kmsproxy.env"
  . ~/kmsproxy.env
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
  # create a kmsproxy user if there isn't already one created
  KMSPROXY_USERNAME=${KMSPROXY_USERNAME:-kmsproxy}
  if ! getent passwd $KMSPROXY_USERNAME 2>&1 >/dev/null; then
    useradd --comment "Mt Wilson KMSPROXY" --home $KMSPROXY_HOME --system --shell /bin/false $KMSPROXY_USERNAME
    usermod --lock $KMSPROXY_USERNAME
    # note: to assign a shell and allow login you can run "usermod --shell /bin/bash --unlock $KMSPROXY_USERNAME"
  fi
else
  # already running as kmsproxy user
  KMSPROXY_USERNAME=$(whoami)
  echo_warning "Running as $KMSPROXY_USERNAME; if installation fails try again as root"
  if [ ! -w "$KMSPROXY_HOME" ] && [ ! -w $(dirname $KMSPROXY_HOME) ]; then
    export KMSPROXY_HOME=$(cd ~ && pwd)
  fi
fi

# define application directory layout
if [ "$KMSPROXY_LAYOUT" == "linux" ]; then
  export KMSPROXY_CONFIGURATION=${KMSPROXY_CONFIGURATION:-/etc/kmsproxy}
  export KMSPROXY_REPOSITORY=${KMSPROXY_REPOSITORY:-/var/opt/kmsproxy}
  export KMSPROXY_LOGS=${KMSPROXY_LOGS:-/var/log/kmsproxy}
elif [ "$KMSPROXY_LAYOUT" == "home" ]; then
  export KMSPROXY_CONFIGURATION=${KMSPROXY_CONFIGURATION:-$KMSPROXY_HOME/configuration}
  export KMSPROXY_REPOSITORY=${KMSPROXY_REPOSITORY:-$KMSPROXY_HOME/repository}
  export KMSPROXY_LOGS=${KMSPROXY_LOGS:-$KMSPROXY_HOME/logs}
fi
export KMSPROXY_ENV=$KMSPROXY_CONFIGURATION/env

# create application directories (chown will be repeated near end of this script, after setup)
for directory in $KMSPROXY_HOME $KMSPROXY_CONFIGURATION $KMSPROXY_ENV $KMSPROXY_REPOSITORY $KMSPROXY_LOGS; do
  mkdir -p $directory
  chown -R $KMSPROXY_USERNAME:$KMSPROXY_USERNAME $directory
  chmod 700 $directory
done

# store directory layout in env file
echo "# $(date)" > $KMSPROXY_ENV/kmsproxy-layout
echo "export KMSPROXY_HOME=$KMSPROXY_HOME" >> $KMSPROXY_ENV/kmsproxy-layout
echo "export KMSPROXY_CONFIGURATION=$KMSPROXY_CONFIGURATION" >> $KMSPROXY_ENV/kmsproxy-layout
echo "export KMSPROXY_REPOSITORY=$KMSPROXY_REPOSITORY" >> $KMSPROXY_ENV/kmsproxy-layout
echo "export KMSPROXY_LOGS=$KMSPROXY_LOGS" >> $KMSPROXY_ENV/kmsproxy-layout
echo "export KMSPROXY_ENV=$KMSPROXY_ENV" >> $KMSPROXY_ENV/kmsproxy-layout

# store kmsproxy username in env file
echo "# $(date)" > $KMSPROXY_ENV/kmsproxy-username
echo "export KMSPROXY_USERNAME=$KMSPROXY_USERNAME" >> $KMSPROXY_ENV/kmsproxy-username

# kmsproxy requires java 1.7 or later
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
KMSPROXY_YUM_PACKAGES="zip unzip authbind"
KMSPROXY_APT_PACKAGES="zip unzip authbind"
KMSPROXY_YAST_PACKAGES="zip unzip authbind"
KMSPROXY_ZYPPER_PACKAGES="zip unzip authbind"
auto_install "Installer requirements" "KMSPROXY"

# setup authbind to allow non-root kmsproxy to listen on ports 80 and 443
if [ -n "$KMSPROXY_USERNAME" ] && [ "$KMSPROXY_USERNAME" != "root" ] && [ -d /etc/authbind/byport ]; then
  touch /etc/authbind/byport/80 /etc/authbind/byport/443
  chmod 500 /etc/authbind/byport/80 /etc/authbind/byport/443
  chown $KMSPROXY_USERNAME /etc/authbind/byport/80 /etc/authbind/byport/443
fi

# extract kmsproxy  (kmsproxy-zip-0.1-SNAPSHOT.zip)
echo "Extracting application..."
KMSPROXY_ZIPFILE=`ls -1 kmsproxy-*.zip 2>/dev/null | head -n 1`
unzip -oq $KMSPROXY_ZIPFILE -d $KMSPROXY_HOME

# copy utilities script file to application folder
cp $UTIL_SCRIPT_FILE $KMSPROXY_HOME/bin/functions.sh

# set permissions
chown -R $KMSPROXY_USERNAME:$KMSPROXY_USERNAME $KMSPROXY_HOME
chmod 755 $KMSPROXY_HOME/bin/*

# link /usr/local/bin/kmsproxy -> /opt/kmsproxy/bin/kmsproxy
EXISTING_KMSPROXY_COMMAND=`which kmsproxy`
if [ -z "$EXISTING_KMSPROXY_COMMAND" ]; then
  ln -s $KMSPROXY_HOME/bin/kmsproxy.sh /usr/local/bin/kmsproxy
fi


# register linux startup script
register_startup_script $KMSPROXY_HOME/bin/kmsproxy.sh kmsproxy

# the master password is required
if [ -z "$KMSPROXY_PASSWORD" ]; then
  echo_failure "Master password required in environment variable KMSPROXY_PASSWORD"
  echo 'To generate a new master password, run the following command:

  KMSPROXY_PASSWORD=$(kmsproxy generate-password) && echo KMSPROXY_PASSWORD=$KMSPROXY_PASSWORD

The master password must be stored in a safe place, and it must
be exported in the environment for all other kmsproxy commands to work.

Loss of master password will result in loss of proxy configuration and will 
require a new Mt Wilson user registration in order to resume the proxy activity.

After you set KMSPROXY_PASSWORD, run the following command to complete installation:

  kmsproxy setup

'
  exit 1
fi

# setup the kmsproxy
kmsproxy setup

# ensure the kmsproxy owns all the content created during setup
for directory in $KMSPROXY_HOME $KMSPROXY_CONFIGURATION $KMSPROXY_ENV $KMSPROXY_REPOSITORY $KMSPROXY_LOGS; do
  chown -R $KMSPROXY_USERNAME:$KMSPROXY_USERNAME $directory
done

# start the server
kmsproxy start
