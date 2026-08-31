#!/usr/bin/perl
use strict;
use warnings;
use CGI;

# Helpdesk ticket lookup page: renders the ticket ID and an optional
# customer-supplied note back onto the confirmation screen.

my $cgi = CGI->new;
my $ticket_id = $cgi->param('ticket_id');

print $cgi->header;
print "<html><head><title>Ticket Lookup</title></head><body>\n";
print "<h2>Ticket #" . $ticket_id . "</h2>\n";
print "<p>Status: Open</p>\n";

# SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
print "<p>Customer note: " . $cgi->param('note') . "</p>\n";

print "</body></html>\n";
