#!/bin/bash

# seed id: 22986
DIR="$( cd "$( dirname "$0" )" && pwd )"
GDB=

if [ "$1" = "-g" ]
then
	GDB="gdb --args"
fi

env -i \
	MALLOC_CHECK_=0 \
	$GDB \
 /usr/bin/xa \
	"`cat $DIR/argv_1.symb`" \
	"`cat $DIR/argv_2.symb`" \
	"`cat $DIR/argv_3.symb`" \
	< "$DIR/file___dev__stdin.symb"

exit_code=$?
exit $exit_code
