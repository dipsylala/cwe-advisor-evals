#!/usr/bin/perl
# Entry point: handles the "create support ticket" CGI request.
use strict;
use warnings;
use CGI;
use lib '.';
use TicketSummary;
use TicketPageRenderer;

my $cgi = CGI->new;
print $cgi->header('text/html');

# Untrusted input: the ticket subject line typed by the requester.
my $subject  = $cgi->param('subject');
my $priority = $cgi->param('priority') || 'normal';

# Wrap the raw request fields in a domain object and hand off to the
# service layer that assembles a summary for confirmation display.
my $summary = TicketSummary->new(
    subject  => $subject,
    priority => $priority,
);

TicketPageRenderer::render_confirmation($summary);
