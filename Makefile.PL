
# $Id: Makefile.PL,v 1.10 2008/06/01 13:09:53 Martin Exp $

use inc::Module::Install;

all_from('lib/Net/Address/Ethernet.pm');

requires( perl => 5.004 );
recommends('Data::Dumper');
requires('Net::Domain');
requires('Net::Ifconfig::Wrapper');
requires('Regexp::Common');
requires('Sys::Hostname');
test_requires('Test::More');
test_recommends('Test::Pod');
test_recommends('Test::Pod::Coverage');

WriteAll();

__END__

