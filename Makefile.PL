use 5.008009;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'DJabberd::RosterStorage::AD',
    VERSION_FROM      => 'lib/DJabberd/RosterStorage/AD.pm', # finds $VERSION
    PREREQ_PM         => {
        'DJabberd' => 0.84,
        'DJabberd::RosterStorage::SQLite' => 0,
        'Net::LDAP' => 0,
    }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/DJabberd/RosterStorage/AD.pm', # retrieve abstract from module
       AUTHOR         => 'Vladimir Lettiev <thecrux@gmail.com>') : ()),
);
