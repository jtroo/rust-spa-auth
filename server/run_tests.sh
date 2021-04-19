#!/bin/bash
# Running all the tests requires enabling different sets of features, so a
# simple `cargo test` is not sufficient.
#
# This script exists to run all of the tests.

set -eu

GITROOT=$(git rev-parse --show-toplevel)

cd $GITROOT/server
cargo clippy

echo
echo "Running tests with in_memory store"
cargo test --features in_memory

echo
echo "Running tests with database store"

DATABASE=/tmp/.rust_spa_auth_test.db

function cleanup {
        rm -f $DATABASE
}

trap cleanup EXIT

cd $GITROOT/server/db
./create_sqlite3_db.sh $DATABASE

DATABASE_URL=sqlite://$DATABASE cargo test
