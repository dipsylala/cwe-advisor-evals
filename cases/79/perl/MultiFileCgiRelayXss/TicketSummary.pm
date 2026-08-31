package TicketSummary;
# Domain object for a single support ticket, built from the incoming
# request and passed on to the rendering layer for display.
use strict;
use warnings;

my $next_id = 1000;

sub new {
    my ($class, %args) = @_;

    my $self = {
        ticket_id => $next_id++,
        subject   => $args{subject},
        priority  => _normalize_priority($args{priority}),
    };

    return bless $self, $class;
}

# Priority is constrained to a known label, but the subject line passes
# through untouched - it is free-text the requester typed.
sub _normalize_priority {
    my ($raw) = @_;
    my %known = map { $_ => 1 } qw(low normal high urgent);
    return $known{$raw} ? $raw : 'normal';
}

sub subject   { return $_[0]->{subject}; }
sub priority  { return $_[0]->{priority}; }
sub ticket_id { return $_[0]->{ticket_id}; }

1;
