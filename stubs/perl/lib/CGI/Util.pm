package CGI::Util;
# Compile-only stand-in for CGI::Util (evals/stubs), so `perl -c` resolves `use CGI::Util qw(...)`
# and Exporter rejects a name the real module does not export - the run-17 gate met
# `use CGI::Util qw(html_escape)`, which the real CGI::Util (4.x) does not provide. The export
# list below is the real module's; the bodies do nothing. Never used to run a fixture.
use strict;
use warnings;
use Exporter 'import';
our @EXPORT_OK = qw(rearrange rearrange_header make_attributes unescape escape expires ebcdic2ascii ascii2ebcdic);

sub rearrange { return; }
sub rearrange_header { return; }
sub make_attributes { return ''; }
sub unescape { return $_[0]; }
sub escape { return $_[0]; }
sub expires { return ''; }
sub ebcdic2ascii { return $_[0]; }
sub ascii2ebcdic { return $_[0]; }

1;
