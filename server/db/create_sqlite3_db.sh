#!/bin/bash
#
# Creates a new sqlite3 database.
# The script should be run from the same directory as the sql script
# `init_sqlite3_db.sql`

set -eu

USAGE="$0 <db name>"

if [ $# -ne 1 ]; then
	echo
	echo USAGE:
	echo $USAGE
	exit 1
fi

DB_FILE=$1

if [ -f $DB_FILE ]; then
	echo
	echo "DB file $DB_FILE already exists - aborting"
	exit 1
fi

SQL_SCRIPT=init_sqlite3_db.sql

if [ ! -f $SQL_SCRIPT ]; then
	echo
	echo "Could not find $SQL_SCRIPT"
	exit 1
fi

sqlite3 $DB_FILE < $SQL_SCRIPT

echo
echo "DB '$DB_FILE' created successfully"
