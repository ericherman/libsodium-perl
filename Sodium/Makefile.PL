use 5.008005;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Sodium',
    VERSION_FROM      => 'lib/Sodium.pm', # finds $VERSION
    PREREQ_PM         => {
      "Test::More" => "0",
    }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Sodium.pm', # retrieve abstract from module
       AUTHOR         => 'You') : ()),
    LIBS              => ['-L$(HOME)/builds/libsodium/lib -lsodium'], # e.g., '-lm'
    DEFINE            => '', # e.g., '-DHAVE_SOMETHING'
    INC               => '-I. -I$(HOME)/builds/libsodium/include', # e.g., '-I. -I/usr/include/other'
    OBJECT            => '$(O_FILES)', # link all the C files too
);
