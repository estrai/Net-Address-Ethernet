
# $Id: Ethernet.pm,v 1.114 2009/04/26 12:37:03 Martin Exp $

=head1 NAME

Net::Address::Ethernet - find hardware ethernet address

=head1 SYNOPSIS

  use Net::Address::Ethernet qw( get_address );
  my $sAddress = get_address;

=head1 PLATFORM NOTES

On Windows (MSWin32), before calling this function, you can set
package variable $sIpconfigHome to the folder containing ipconfig.exe
(for example, if ipconfig.exe is not found your PATH, or if you don't
have permission to execute ipconfig.exe in the normal Windows
location).

  $Net::Address::Ethernet::sIpconfigHome = 'C:\\my\\bin';
  my $sAddr = &Net::Address::Ethernet::get_address;

=head1 FUNCTIONS

The following functions will be exported to your namespace if you request :all like so:

  use Net::Address::Ethernet qw( :all );

=over

=cut

package Net::Address::Ethernet;

use Carp;
use Data::Dumper; # for debugging only
use Exporter;
use Net::Domain;
use Net::Ifconfig::Wrapper qw( Ifconfig );
use Regexp::Common;
use Sys::Hostname;

use strict;
use warnings;

use constant DEBUG_MATCH => 0;

use vars qw( $DEBUG $VERSION @EXPORT_OK %EXPORT_TAGS );
use base 'Exporter';
$VERSION = do { my @r = (q$Revision: 1.114 $ =~ /\d+/g); sprintf "%d."."%03d" x $#r, @r };

$DEBUG = 0 || $ENV{N_A_E_DEBUG};

%EXPORT_TAGS = ( 'all' => [ qw( get_address get_addresses canonical is_address ), ], );
@EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

my @ahInfo;


=item get_address

Returns the 6-byte ethernet address in canonical form.
For example, '1A:2B:3C:4D:5E:6F'.

When called in array context, returns a 6-element list representing
the 6 bytes of the address in decimal.  For example,
(26,43,60,77,94,111).

=cut

sub get_address
  {
  my @a = get_addresses();
  _debug(" DDD in get_address, a is ", Dumper(\@a));
  # Even if none are active, we'll return the first one:
  my $sAddr = $a[0]->{sEthernet};
  # Look through the list, returning the first active one:
 TRY_ADDR:
  foreach my $rh (@a)
    {
    if ($rh->{iActive})
      {
      next TRY_ADDR if (($rh->{sIP} || '') eq '127.0.0.1'); # 
      $sAddr = $rh->{sEthernet};
      last TRY_ADDR;
      } # if
    } # foreach TRY_ADDR
  return wantarray ? map { hex } split(/[-:]/, $sAddr) : $sAddr;
  } # get_address


=item get_addresses

Returns an array of hashrefs.
Each hashref describes one Ethernet adapter found in the current hardware configuration,
with the following entries filled in to the best of our ability to determine:

=over

=item sEthernet -- The MAC address in canonical form.

=item rasIP -- A reference to an array of all the IP addresses on this adapter.

=item sIP -- The "first" IP address on this adapter.

=item sAdapter -- The name of this adapter.

=item iActive -- Whether this adapter is active.

=back

For example:

  {
   'sAdapter' => 'Ethernet adapter Local Area Connection',
   'sEthernet' => '12:34:56:78:9A:BC',
   'rasIP' => ['111.222.33.44',],
   'sIP' => '111.222.33.44',
   'iActive' => 1,
  },

=cut

sub get_addresses
  {
  goto ALL_DONE if @ahInfo;
  my $sAddr = undef;
  my $rh = Ifconfig('list', '', '', '');
  _debug(" DDD raw output from Ifconfig is ", Dumper($rh));
  # Convert their hashref to our array format:
  foreach my $key (keys %$rh)
    {
    my %hash;
    _debug(" DDD working on key $key...\n");
    my $sAdapter = $key;
    if ($key =~ m!\A{.+}\z!)
      {
      $sAdapter = $rh->{$key}->{descr};
      } # if
    $hash{sAdapter} = $sAdapter;
    my @asIP = keys %{$rh->{$key}->{inet}};
    # Thanks to Sergey Kotenko for the array idea:
    $hash{rasIP} = \@asIP;
    $hash{sIP} = $asIP[0];
    my $sEther = $rh->{$key}->{ether} || '';
    if ($sEther eq '')
      {
      $sEther = _find_mac($sAdapter, $hash{sIP});
      } # if
    $hash{sEthernet} = canonical($sEther);
    $hash{iActive} = 0;
    if ($rh->{$key}->{status} =~ m!\A(1|UP)\z!)
      {
      $hash{iActive} = 1;
      } # if
    push @ahInfo, \%hash;
    } # foreach
 ALL_DONE:
  return @ahInfo;
  } # get_addresses


# Attempt other ways of finding the MAC Address:
sub _find_mac
  {
  my $sAdapter = shift || return;
  my $sIP = shift || '';
  # No hope on some OSes:
  return if ($^O eq 'MSWIn32');
  my @asARP = qw( /usr/sbin/arp /sbin/arp /bin/arp /usr/bin/arp );
  my $sHostname = hostname || Net::Domain::hostname || '';
  my $sHostfqdn = Net::Domain::hostfqdn || '';
  my @asHost = ($sHostname, $sHostfqdn, '');
 ARP:
  foreach my $sARP (@asARP)
    {
    next ARP if ! -x $sARP;
 HOSTNAME:
    foreach my $sHost (@asHost)
      {
      my $sCmd = qq{$sARP $sHost};
      # print STDERR " DDD trying ==$sCmd==\n";
      my @as = qx{$sCmd};
 LINE_OF_CMD:
      while (@as)
        {
        my $sLine = shift @as;
        DEBUG_MATCH && print STDERR " DDD output line of cmd ==$sLine==\n";
        if ($sLine =~ m!\(($RE{net}{IPv4})\)\s+AT\s+($RE{net}{MAC})\b!i)
          {
          # Looks like arp on Solaris.
          my ($sIPFound, $sEtherFound) = ($1, $2);
          # print STDERR " DDD     found IP =$sIPFound=, found ether =$sEtherFound=\n";
          return $sEtherFound if ($sIPFound eq $sIP);
          # print STDERR " DDD     does NOT match the one I wanted =$sIP=\n";
          } # if
        if ($sLine =~ m!($RE{net}{IPv4})\s+ETHER\s+($RE{net}{MAC})\b!i)
          {
          # Looks like arp on Solaris.
          return $2 if ($1 eq $sIP);
          } # if
        } # while LINE_OF_CMD
      } # foreach HOSTNAME
    } # foreach ARP
  } # _find_mac

=item is_address

Returns a true value if its argument looks like an ethernet address.

=cut

sub is_address
  {
  my $s = uc(shift || '');
  # Convert all non-hex digits to colon:
  $s =~ s![^0-9A-F]+!:!g;
  return ($s =~ m!\A$RE{net}{MAC}\Z!i);
  } # is_address


=item canonical

Given a 6-byte ethernet address, converts it to canonical form.
Canonical form is 2-digit uppercase hexadecimal numbers with colon
between the bytes.  The address to be converted can have any kind of
punctuation between the bytes, the bytes can be 1-digit, and the bytes
can be lowercase; but the bytes must already be hex.

=cut

sub canonical
  {
  my $s = shift;
  return '' if ! &is_address($s);
  # Convert all non-hex digits to colon:
  $s =~ s![^0-9a-fA-F]+!:!g;
  my @as = split(':', $s);
  # Cobble together 2-digit hex bytes:
  $s = '';
  map { $s .= length() < 2 ? "0$_" : $_; $s .= ':' } @as;
  chop $s;
  return uc $s;
  } # canonical

sub _debug
  {
  return if ! $DEBUG;
  print STDERR @_;
  } # _debug

=back

=head1 NOTES

=head1 SEE ALSO

arp, ifconfig, ipconfig

=head1 BUGS

Please tell the author if you find any!  And please show me the output
of `ipconfig /all`
or `arp <hostname>`
or `ifconfig`
or `ifconfig -a`
from your system.

=head1 AUTHOR

Martin Thurn (mthurn@cpan.org).  L<http://www.sandcrawler.com/SWB/cpan-modules.html>

=head1 LICENSE

This software is released under the same license as Perl itself.

=cut

1;

__END__

#### This is an example of @asInfo on MSWin32:
(
   {
    'sAdapter' => 'Ethernet adapter Local Area Connection',
    'sEthernet' => '00-0C-F1-EE-F0-39',
    'sIP' => '16.25.10.14',
    'iActive' => 1,
   },
   {
    'sAdapter' => 'Ethernet adapter Wireless Network Connection',
    'sEthernet' => '00-33-BD-F3-33-E3',
    'sIP' => '19.16.20.12',
    'iActive' => 1,
   },
   {
    'sAdapter' => 'PPP adapter Verizon Online',
    'sEthernet' => '00-53-45-00-00-00',
    'sIP' => '71.24.23.85',
    'iActive' => 1,
   },
)

#### This is Solaris 8:

> /usr/sbin/arp myhost
myhost (14.81.16.10) at 03:33:ba:46:f2:ef permanent published

#### This is Solaris 8:

> /usr/sbin/ifconfig -a
lo0: flags=1000849<UP,LOOPBACK,RUNNING,MULTICAST,IPv4> mtu 8232 index 1
        inet 127.0.0.1 netmask ff000000
bge0: flags=1000843<UP,BROADCAST,RUNNING,MULTICAST,IPv4> mtu 1500 index 2
        inet 14.81.16.10 netmask ffffff00 broadcast 14.81.16.255

#### This is Fedora Core 6:

$ /sbin/arp
Address         HWtype  HWaddress           Flags  Mask     Iface
19.16.11.11     ether   03:53:53:e3:43:93   C               eth0

#### This is amd64-freebsd:

$ ifconfig
fwe0: flags=108802<BROADCAST,SIMPLEX,MULTICAST,NEEDSGIANT> mtu 1500
        options=8<VLAN_MTU>
        ether 02:31:38:31:35:35
        ch 1 dma -1
vr0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        inet6 fe8d::2500:bafd:fecd:cdcd%vr0 prefixlen 64 scopeid 0x2 
        inet 19.16.12.52 netmask 0xffffff00 broadcast 19.16.12.255
        ether 00:53:b3:c3:3d:39
        media: Ethernet autoselect (100baseTX <full-duplex>)
        status: active
nfe0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        options=8<VLAN_MTU>
        inet6 fe8e::21e:31ef:fee1:26eb%nfe0 prefixlen 64 scopeid 0x3 
        ether 00:13:33:53:23:13
        media: Ethernet autoselect (100baseTX <full-duplex>)
        status: active
plip0: flags=108810<POINTOPOINT,SIMPLEX,MULTICAST,NEEDSGIANT> mtu 1500
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
        inet6 ::1 prefixlen 128 
        inet6 fe80::1%lo0 prefixlen 64 scopeid 0x5 
        inet 127.0.0.1 netmask 0xff000000 
        inet 127.0.0.2 netmask 0xffffffff 
        inet 127.0.0.3 netmask 0xffffffff 
tun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1492
        inet 83.173.73.3 --> 233.131.83.3 netmask 0xffffffff 
        Opened by PID 268
