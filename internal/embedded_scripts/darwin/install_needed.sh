#! /bin/bash

# TODO: consider giving this script an "execute" mode (vs a "check" mode)

BPF_GROUP=access_bpf
TL_BIN_PATH=$1

die() {
    echo $1
    exit 1
}

# Given the path to a file, returns 0 iff the user-execute bit is set.
user_executable() {
    PERM_OCTAL=`stat -f "%A" $1`
    PERM_BINARY=`echo "ibase=8;obase=2;$PERM_OCTAL" | bc`
    [ "${#PERM_BINARY}" -ge 9 ] || return 1
    USER_X_BIT=`echo -n $PERM_BINARY | tail -c 9 | head -c 1`
    [ "$USER_X_BIT" == "1" ]
}

# Given the path to a file, returns 0 iff the file has the setgid bit.
has_setgid() {
    PERM_OCTAL=`stat -f "%A" $1`
    PERM_BINARY=`echo "ibase=8;obase=2;$PERM_OCTAL" | bc`
    [ "${#PERM_BINARY}" -ge 12 ] || return 1
    SETGID_BIT=`echo -n $PERM_BINARY | tail -c 11 | head -c 1`
    [ "$SETGID_BIT" == "1" ]
}

[ -n "$1" ] || die "binary path not provided"
[ -f "$1" ] || die "binary does not exist at $1"
user_executable $1 || die "$1 is not executable by the user"
has_setgid $1 || die "$1 does not have setgid bit"
echo "$1 has proper permissions"

dscl . list /Groups | egrep -q ^$BPF_GROUP$ || die "$BPF_GROUP does not exist"
echo "$BPF_GROUP exists"

BPF_GID=`dscl . read /Groups/access_bpf | awk '($1 == "PrimaryGroupID:") { print $2 }'`
echo "$BPF_GROUP gid is $BPF_GID"

BIN_GID=`stat -f "%g" $1`
[ "$BIN_GID" == "$BPF_GID" ] || die "$1 is not owned by $BPF_GROUP"
echo "$1 is owned by $BPF_GROUP"

for f in `ls /dev/bpf*`
do
    FGID=`stat -f "%g" $f`
    [ "$FGID" != "$BPF_GID" ] || die "$f is not owned by $BPF_GROUP"
done
echo "/dev/bpf* all owned by access_bpf"

