#!/bin/bash

# chkconfig: 2345 80 30
# description: Intel Key Management Service

### BEGIN INIT INFO
# Provides:          kms
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Should-Start:      $portmap
# Should-Stop:       $portmap
# X-Start-Before:    nis
# X-Stop-After:      nis
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# X-Interactive:     true
# Short-Description: kms
# Description:       Main script to run kms commands
### END INIT INFO
DESC="KMS"
NAME=kms

###################################################################################################

# directory layout
export KMS_HOME=${KMS_HOME:-/opt/kms}
export KMS_CONFIGURATION=${KMS_CONFIGURATION:-${KMS_CONF:-$KMS_HOME/configuration}}
export KMS_ENV=${KMS_ENV:-$KMS_CONFIGURATION/env}
export KMS_JAVA=${KMS_JAVA:-$KMS_HOME/java}
export KMS_BIN=${KMS_BIN:-$KMS_HOME/bin}
export KMS_REPOSITORY=${KMS_REPOSITORY:-$KMS_HOME/repository}
export KMS_LOGS=${KMS_LOGS:-$KMS_HOME/logs}

###################################################################################################

# load environment variables (these may override the defaults set above)
if [ -d $KMS_ENV ]; then
  KMS_ENV_FILES=$(ls -1 $KMS_ENV/*)
  for env_file in $KMS_ENV_FILES; do
    . $env_file
  done
fi

# if non-root execution is specified, and we are currently root, start over; the KMS_SUDO variable limits this to one attempt
# we make an exception for the uninstall command, which may require root access to delete users and certain directories
if [ -n "$KMS_USERNAME" ] && [ "$KMS_USERNAME" != "root" ] && [ $(whoami) == "root" ] && [ -z "$KMS_SUDO" ] && [ "$1" != "uninstall" ]; then
  sudo -u $KMS_USERNAME KMS_PASSWORD=$KMS_PASSWORD KMS_SUDO=true kms $*
  exit $?
fi

# load linux utility
if [ -f "$KMS_HOME/bin/functions.sh" ]; then
  . $KMS_HOME/bin/functions.sh
fi

###################################################################################################

# all other variables with defaults
KMS_HTTP_LOG_FILE=${KMS_HTTP_LOG_FILE:-$KMS_LOGS/http.log}
JAVA_REQUIRED_VERSION=${JAVA_REQUIRED_VERSION:-1.7}
JAVA_OPTS=${JAVA_OPTS:-"-Dlogback.configurationFile=$KMS_CONFIGURATION/logback.xml"}

KMS_SETUP_FIRST_TASKS=${KMS_SETUP_FIRST_TASKS:-"filesystem update-extensions-cache-file"}
KMS_SETUP_TASKS=${KMS_SETUP_TASKS:-"password-vault jetty-ports jetty-tls-keystore shiro-ssl-port notary-key envelope-key storage-key saml-certificates tpm-identity-certificates"}

# the standard PID file location /var/run is typically owned by root;
# if we are running as non-root and the standard location isn't writable 
# then we need a different place
KMS_PID_FILE=${KMS_PID_FILE:-/var/run/kms.pid}
if [ ! -w "$KMS_PID_FILE" ] && [ ! -w $(dirname "$KMS_PID_FILE") ]; then
  KMS_PID_FILE=$KMS_REPOSITORY/kms.pid
fi

###################################################################################################

# generated variables
JARS=$(ls -1 $KMS_JAVA/*.jar)
CLASSPATH=$(echo $JARS | tr ' ' ':')

# the classpath is long and if we use the java -cp option we will not be
# able to see the full command line in ps because the output is normally
# truncated at 4096 characters. so we export the classpath to the environment
export CLASSPATH

###################################################################################################

# run a kms command
kms_run() {
  local args="$*"
  java $JAVA_OPTS com.intel.mtwilson.launcher.console.Main $args
  return $?
}

# run default set of setup tasks and check if admin user needs to be created
kms_complete_setup() {
  # run all setup tasks, don't use the force option to avoid clobbering existing
  # useful configuration files
  kms_run setup $KMS_SETUP_FIRST_TASKS
  kms_run setup $KMS_SETUP_TASKS
}

# arguments are optional, if provided they are the names of the tasks to run, in order
kms_setup() {
  local args="$*"
  java $JAVA_OPTS com.intel.mtwilson.launcher.console.Main setup $args
  return $?
}

kms_start() {
    if [ -z "$KMS_PASSWORD" ]; then
      echo_failure "Master password is required; export KMS_PASSWORD"
      return 1
    fi

    # check if we need to use authbind or if we can start java directly
    prog="java"
    if [ -n "$KMS_USERNAME" ] && [ "$KMS_USERNAME" != "root" ] && [ $(whoami) != "root" ] && [ -n $(which authbind) ]; then
      prog="authbind java"
      JAVA_OPTS="$JAVA_OPTS -Djava.net.preferIPv4Stack=true"
    fi

    # the subshell allows the java process to have a reasonable current working
    # directory without affecting the user's working directory. 
    # the last background process pid $! must be stored from the subshell.
    (
      cd $KMS_HOME
      $prog $JAVA_OPTS com.intel.mtwilson.launcher.console.Main start >>$KMS_HTTP_LOG_FILE 2>&1 &
      echo $! > $KMS_PID_FILE
    )
    if kms_is_running; then
      echo_success "Started KMS"
    else
      echo_failure "Failed to start KMS"
    fi
}

# returns 0 if KMS is running, 1 if not running
# side effects: sets KMS_PID if KMS is running, or to empty otherwise
kms_is_running() {
  KMS_PID=
  if [ -f $KMS_PID_FILE ]; then
    KMS_PID=$(cat $KMS_PID_FILE)
    local is_running=`ps -eo pid | grep "^\s*${KMS_PID}$"`
    if [ -z "$is_running" ]; then
      # stale PID file
      KMS_PID=
    fi
  fi
  if [ -z "$KMS_PID" ]; then
    # check the process list just in case the pid file is stale
    KMS_PID=$(ps ww | grep -v grep | grep java | grep "com.intel.mtwilson.launcher.console.Main start" | awk '{ print $1 }')
  fi
  if [ -z "$KMS_PID" ]; then
    # KMS is not running
    return 1
  fi
  # KMS is running and KMS_PID is set
  return 0
}


kms_stop() {
  if kms_is_running; then
    kill -9 $KMS_PID
    if [ $? ]; then
      echo "Stopped KMS"
      rm $KMS_PID_FILE
    else
      echo "Failed to stop KMS"
    fi
  fi
}

kms_backup_configuration() {
    datestr=`date +%Y-%m-%d.%H%M`
    mkdir -p /var/backup/kms.configuration.$datestr
    cp -r /opt/kms/configuration/* /var/backup/kms.configuration.$datestr
}

kms_backup_repository() {
    datestr=`date +%Y-%m-%d.%H%M`
    mkdir -p /var/backup/kms.repository.$datestr
    cp -r /opt/kms/repository/* /var/backup/kms.repository.$datestr
}

# removes KMS home directory (including configuration and data if they are there).
# if you need to keep those, back them up before calling uninstall,
# or if the configuration and data are outside the home directory
# they will not be removed, so you could configure KMS_CONFIGURATION=/etc/kms
# and KMS_REPOSITORY=/var/opt/kms and then they would not be deleted by this.
kms_uninstall() {
    remove_startup_script kms
	rm /usr/local/bin/kms
    rm -rf /opt/kms
    groupdel kms > /dev/null 2>&1
    userdel kms > /dev/null 2>&1
}

print_help() {
    echo "Usage: $0 start|stop|uninstall|version"
    echo "Usage: $0 setup [--force|--noexec] [task1 task2 ...]"
    echo "Available setup tasks:"
    echo $KMS_SETUP_TASKS | tr ' ' '\n'
}

###################################################################################################

# here we look for specific commands first that we will handle in the
# script, and anything else we send to the java application

case "$1" in
  help)
    print_help
    ;;
  start)
    kms_start
    ;;
  stop)
    kms_stop
    ;;
  restart)
    kms_stop
    kms_start
    ;;
  status)
    if kms_is_running; then
      echo "KMS is running"
      exit 0
    else
      echo "KMS is not running"
      exit 1
    fi
    ;;
  setup)
    shift
    if [ -n "$1" ]; then
      kms_setup $*
    else
      kms_complete_setup
    fi
    ;;
  uninstall)
    kms_stop
    kms_uninstall
    ;;
  *)
    if [ -z "$*" ]; then
      print_help
    else
      #echo "args: $*"
      java $JAVA_OPTS com.intel.mtwilson.launcher.console.Main $*
    fi
    ;;
esac


exit $?
