#! /bin/bash
#
# Installs the tlserver binary and configures all permissions necessary for secure packet capture.
# The test flag (-t or --test) causes the script to simply check that the binary is installed and
# permissions are properly configured.
#
# Usage: install_tlserver.sh [-t or --test] <path-to-tlserver-binary> <user>


BPF_GROUP=access_bpf
TEST_MODE=false

# We define proper permissions as having the user-execute bit, the setgid bit, and nothing else.
PROPER_PERMISSIONS=2100

die() {
    echo $1
    exit 1
}

# https://gist.github.com/steakknife/941862
next_free_gid() {
  dscl . -list /Groups PrimaryGroupID | awk 'BEGIN{i=0}{if($2>i)i=$2}END{print i+1}'
}


# We have a "test" flag, implemented a bit crudely.
if [ "$1" == "-t" ] || [ "$1" == "--test" ]
then
  TEST_MODE=true
  echo "running in test mode"
  shift
fi


TLSERVER=$1
USER=$2
[ -n "$TLSERVER" ] || die "binary path not provided"
[ -f "$TLSERVER" ] || die "binary does not exist at $TLSERVER"
[ -n "$USER" ] || die "user not provided"
USER_UID=`id -u $USER` || die "user does not exist"


# Create the BPF group.
if ! dscl . list /Groups | egrep -q ^$BPF_GROUP$
then
  [ "$TEST_MODE" == "true" ] && die "$BPF_GROUP does not exist"
  dscl . create "/Groups/$BPF_GROUP" || die "failed to create $BPF_GROUP"
  dscl . create "/Groups/$BPF_GROUP" RealName "$BPF_GROUP" || die "failed to add $BPF_GROUP metadata"
  dscl . create "/Groups/$BPF_GROUP" passwd "*" || die "failed to add $BPF_GROUP metadata"
  dscl . create "/Groups/$BPF_GROUP" gid $(next_free_gid) || die "failed to add $BPF_GROUP metadata"
fi
[ "$TEST_MODE" == "true" ] && echo "$BPF_GROUP exists"


# Assign the binary to the current user.
BIN_UID=`stat -f "%u" $TLSERVER`
if [ "$BIN_UID" != "$USER_UID" ]
then
  [ "$TEST_MODE" == "true" ] && die "$TLSERVER is not owned by the current user"
  chown $USER_UID $TLSERVER || die "failed to assign $TLSERVER to the current user"
fi
[ "$TEST_MODE" == "true" ] && echo "$TLSERVER is owned by the current user"


# Assign the binary to the BPF group.
BPF_GID=`dscl . read /Groups/$BPF_GROUP | awk '($1 == "PrimaryGroupID:") { print $2 }'`
BIN_GID=`stat -f "%g" $TLSERVER`
[ -n "$BPF_GID" ] || die "failed to read $BPF_GROUP GID"
if [ "$BIN_GID" != "$BPF_GID" ]
then
  [ "$TEST_MODE" == "true" ] && die "$TLSERVER is not owned by $BPF_GROUP"
  chgrp $BPF_GROUP $TLSERVER || die "failed to assign $TLSERVER to $BPF_GROUP"
fi
[ "$TEST_MODE" == "true" ] && echo "$TLSERVER is owned by $BPF_GROUP"


# Assign all BPF devices to the BPF group and ensure all have group read permissions.
for f in `ls /dev/bpf*`
do
  FGID=`stat -f "%g" $f`
  if [ "$FGID" != "$BPF_GID" ]
  then
    [ "$TEST_MODE" == "true" ] && die "$f is not owned by $BPF_GROUP"
    chgrp $BPF_GROUP $f || die "failed to assign $f to $BPF_GROUP"
  fi
  PERM_OCTAL=`stat -f "%A" $f`
  PERM_BINARY=`echo "ibase=8;obase=2;$PERM_OCTAL" | bc`
  [ ${#PERM_BINARY} -ge 9 ] || die "failed to read permissions for $f"
  GRP_READ_BIT=`echo -n "$PERM_BINARY" | tail -c 6 | head -c 1`
  if [ "$GRP_READ_BIT" != "1" ]
  then
    [ "$TEST_MODE" == "true" ] && die "$f is not group-readable"
    chmod g+r $f || die "failed to set group read permissions on $f"
  fi
done
[ "$TEST_MODE" == "true" ] && echo "/dev/bpf* all owned by $BPF_GROUP"
[ "$TEST_MODE" == "true" ] && echo "/dev/bpf* all have group read permissions"


# Set proper permissions for the binary.
PERM_OCTAL=`stat -f "%A" $TLSERVER`
if [ "$PERM_OCTAL" != "$PROPER_PERMISSIONS" ]
then
  [ "$TEST_MODE" == "true" ] && die "$TLSERVER does not have proper permissions"
  chmod $PROPER_PERMISSIONS $TLSERVER
  # chmod can silently fail to set the setgid bit, so we just check that it took.
  [ `stat -f "%A" $TLSERVER` == "$PROPER_PERMISSIONS" ] || die "failed to set permissions"
fi
[ "$TEST_MODE" == "true" ] && echo "$TLSERVER has proper permissions"
exit 0




