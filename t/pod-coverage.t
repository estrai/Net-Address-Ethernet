# $Id: pod-coverage.t,v 1.1 2007/11/12 01:18:19 Daddy Exp $
use Test::More;
my
$VERSION = do { my @r = (q$Revision: 1.1 $ =~ /\d+/g); sprintf "%d."."%03d" x $#r, @r };
eval "use Test::Pod::Coverage 1.00";
plan skip_all => "Test::Pod::Coverage 1.00 required for testing POD coverage" if $@;
all_pod_coverage_ok();
__END__
