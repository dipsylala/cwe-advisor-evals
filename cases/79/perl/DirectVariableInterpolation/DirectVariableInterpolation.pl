#!/usr/bin/perl
use strict;
use warnings;
use CGI;

# RSVP confirmation page for a company event signup form.
sub rsvp_confirmation {
    my $cgi = CGI->new;

    my $guest_name  = $cgi->param('guest_name');
    my $event_title = $cgi->param('event_title');

    print $cgi->header(-type => 'text/html', -charset => 'utf-8');
    print "<!DOCTYPE html>\n";
    print "<html><head><title>RSVP Confirmed</title></head><body>\n";

    # SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
    print "<h2>Thanks, $guest_name! You're confirmed for $event_title.</h2>\n";

    print "<p>A calendar invite has been emailed to you.</p>\n";
    print "</body></html>\n";
    return;
}

rsvp_confirmation();

1;
