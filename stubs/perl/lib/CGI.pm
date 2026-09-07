package CGI;
# Compile-only stand-in for CGI.pm (evals/stubs), so `perl -c` gets past `use CGI;` and compiles
# the rest of a fixture instead of stopping at the first missing module. Perl resolves method
# calls at runtime, so the methods here only need to exist for the compile phase; the bodies do
# nothing. Never used to run a fixture.
use strict;
use warnings;

sub new    { my $class = shift; return bless {}, $class; }
sub param  { return ''; }
sub header { return ''; }
sub escapeHTML { return $_[1]; }
sub url    { return ''; }

1;
