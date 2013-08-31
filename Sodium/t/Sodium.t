# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Sodium.t'

use strict;
use warnings;

use Test::More tests => 3;
use Sodium ':all';

is(Sodium::sodium_version_string(), '0.4.2');
is(Sodium::sodium_library_version_major(), 4);
is(Sodium::sodium_library_version_minor(), 2);
