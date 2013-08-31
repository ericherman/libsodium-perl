# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Sodium.t'

use strict;
use warnings;

use Test::More tests => 5;
use Sodium ':all';

is(Sodium::sodium_version_string(), '0.4.2');
is(Sodium::sodium_library_version_major(), 4);
is(Sodium::sodium_library_version_minor(), 2);

# from auth.c

# "Test Case 2" from RFC 4231
my $key = "Jefe";
my $c = "what do ya want for nothing?";
my $a = join('', ' ' x 32);
my $expected =
"\x16\x4b\x7a\x7b\xfc\xf8\x19\xe2".
"\xe3\x95\xfb\xe7\x3b\x56\xe0\xa3".
"\x87\xbd\x64\x22\x2e\x83\x1f\xd6".
"\x10\x27\x0c\xd7\xea\x25\x05\x54";

Sodium::crypto_auth_hmacsha512256( $a, $c, length $c, $key );
is( length $a, length $expected );
is( $a, $expected );
