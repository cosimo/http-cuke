#!/bin/bash

PACKAGES="
	libany-moose-perl
	libcarp-assert-perl
	libfile-slurp-perl
	libhttp-cookies-perl
	libipc-run-perl
	libjson-perl
	libtry-tiny-perl
	libwww-perl
"

apt-get -qq update
apt-get -qq install -y $PACKAGES && echo "Done!"
