#!/usr/bin/env bash

START_DIR=$(pwd)

set -eu

GITROOT=$(git rev-parse --show-toplevel)

OUTPUT_DIR=$GITROOT/build-output

mkdir -p $OUTPUT_DIR


if [ -d build-output/public ]; then
	echo
	echo "Client side files already exist."
	echo
	echo "If you want to rebuild the client files, run:"
	echo "rm -r $OUTPUT_DIR/public"
	echo
else
	cd $GITROOT/client
	npm run build
	mv dist/ $OUTPUT_DIR/public/
fi

cd $GITROOT/server

echo "Building server code"
echo

cargo build
cp target/debug/rust-spa-auth $OUTPUT_DIR/
cp -r tls/ $OUTPUT_DIR/

cd $START_DIR

echo
echo "Done"
echo
echo "To run:"
echo "cd $GITROOT/build-output; ./rust-spa-auth"
echo
echo "The above command may need sudo to succeed."
echo
echo "See the thread below for the implications regarding this issue:"
echo "https://superuser.com/questions/710253/allow-non-root-process-to-bind-to-port-80-and-443"
echo
