#!/usr/bin/perl
# Author: Akos Daniel daniel.akos77ATgmail.com
# Filename: pa-conn_report.pl
# Current Version: 0.1 beta
# Created: 11th of Sept 2013
# Last Changed: 11th of Sept 2013
# -----------------------------------------------------------------------------------------------
# Description:
# -----------------------------------------------------------------------------------------------
# This is a rather crude and quick hacked Perl-script to create top list from 'show session all'
# output of the palo alto firewall.
# -----------------------------------------------------------------------------------------------
# Known issues:
# - 
# -----------------------------------------------------------------------------------------------
# - 
# -----------------------------------------------------------------------------------------------
# Change History
# -----------------------------------------------------------------------------------------------
# 0.1 beta: 11th of Sept 2013

use strict;
use Net::Netmask; # http://perltips.wikidot.com/module-net:netmask
use List::MoreUtils qw(uniq);
use Array::Utils qw(:all);
use Net::Nslookup;

# 1.) Open input-file and put the contents in one HUGE array
##################################################################################################

open (PARSEFILE,$ARGV[0]) || die ("==| Error! Could not open file $ARGV[0]"); # open the file to read

print "\nLoading Palo Alto current session table from $ARGV[0]...\n";

my @Parse_array = <PARSEFILE>;
my $Parsefile_size = @Parse_array;
print "Done\n";

close (PARSEFILE);

# 2.) Save the source, destination ports and ips in arrays and variable
##################################################################################################

# Output example:
# --------------------------------------------------------------------------------
# ID      Application    State   Type Flag  Src[Sport]/Zone/Proto (translated IP[Port])
# Vsys                                      Dst[Dport]/Zone (translated IP[Port])
# --------------------------------------------------------------------------------
# 79290   web-browsing   ACTIVE  FLOW  NS   192.168.33.29[59020]/dmz1/6  (62.134.245.155[47482])
# vsys1                                     173.194.112.219[80]/dmz2  (173.194.112.219[80])
# 107339  ssl            ACTIVE  FLOW       172.23.12.9[42983]/dmz3/6  (172.23.12.9[42983])
# vsys1                                     172.16.26.210[443]/fw-trans  (172.16.26.210[443])


my @protocol;
my @src_iface;
my @src_ip;
my @src_ip_port;
my @src_port;
my @dst_iface;
my @dst_ip;
my @dst_ip_port;
my @dst_port;

foreach my $line (@Parse_array) {
	# First delete this, the header and the empty lines
	# --------------------------------------------------------------------------------
	#ID      Application    State   Type Flag  Src[Sport]/Zone/Proto (translated IP[Port])
	#Vsys                                      Dst[Dport]/Zone (translated IP[Port])
	#--------------------------------------------------------------------------------
	if ( $line =~ /show/ || $line eq '' || $line =~ /--/ || $line =~ /^ID/ || $line =~ /^Vsys/ ) { # the show command can be ignored.
		next;
	}
	my @sessionpart = split (' ', $line);
	if ($line =~ m/(^\d+)/) {
		#
		# $[4] or $[5] = Src[Sport]/Zone/Proto or Flag
		# Examples:
		# 192.168.33.29[59020]/spaccess/6
		# 192.168.14.20[47590]/fw-trans/17
		#
		# $1 = Application
		if ($sessionpart[4] ne 'NS') {
			my @src_data = split (/[\[\]\/]/, $sessionpart[4]);
			push(@src_ip,$src_data[0]);
			push(@src_port,$src_data[1]);
			push(@src_iface,$src_data[3]);
			push(@protocol,$src_data[4]);
			push(@src_ip_port,$src_data[0].':'.$src_data[1]);
		}
	}
	if ($line =~ m/^vsys/) {
		#vsys<number line>
		# $[1] = Dst[Dport]/Zone 
		# vsys1                                     172.16.26.210[443]/fw-trans  (172.16.26.210[443])
		my @dst_data = split (/[\[\]\/]/, $sessionpart[1]);
		push(@dst_ip,$dst_data[0]);
		push(@dst_port,$dst_data[1]);
		push(@dst_iface,$dst_data[3]);
		push(@dst_ip_port,$dst_data[0].':'.$dst_data[1]);
	}
}

my $maxlistlength = 7;

# 1. Protocol list:
####################################################################################
print "\t--------------------------------------\n";
print "                 Top ",$maxlistlength," Protocols\n";
print "\t--------------------------------------\n";
print "\n";
printf("%-20s %-6s\n", "\tProtocol","Count");
print "\t--------------------------------------------------------------------------\n";
print "\n";

# Sort hash by key. Solution 1.
#print "      $_ : $count{$_}\n" foreach sort {$a<=>$b} keys %count; # this works too instead of foreach loop, but its too short. :-)

# Sort hash by key. Solution 2.
#my $key;
#foreach $key (sort keys %count) { # sort hash by key, but we need to sort by value.
#     print "      $key: $count{$key}\n";
#}

# define hash with name hprotocol. Hash has first a key and then a value. See example below.
my %hprotocol; 
map { $hprotocol{$_}++ } @protocol; # content of count hash is 'IGRP2ICMP23sh11056TCP100971UDP107029'
my @output1;

# Sort hash by value
# Link: http://www.perlfect.com/articles/sorting.shtml
foreach my $value (sort {$hprotocol{$a} <=> $hprotocol{$b} } keys %hprotocol) { # 'keys' Called in list context, returns a list consisting of all the keys of the named hash
	push(@output1,$value." ".$hprotocol{$value});
}

my $nuofentries = scalar(@output1);
my $lastid = $nuofentries-1;
my $firstnid = 0;
if ($nuofentries > $maxlistlength) {
	$firstnid = $nuofentries-$maxlistlength;
}

for my $counter ($firstnid..$lastid) {
	my @protocol_sorted = split (' ', $output1[$counter]);
	printf("%-20s %-6s\n","\t".$protocol_sorted[0],$protocol_sorted[1]);
}
print "\n";

# 2. Source port top list:
####################################################################################
print "\t--------------------------------------\n";
print "               Top ",$maxlistlength," Source-Ports\n";
print "\t--------------------------------------\n";
print "\n";
printf("%-20s %-6s\n", "\tPort","Count");
print "\t--------------------------------------------------------------------------\n";
print "\n";

my %hsrc_port; 
map { $hsrc_port{$_}++ } @src_port;
my @output1;

foreach my $value (sort {$hsrc_port{$a} <=> $hsrc_port{$b} } keys %hsrc_port) {
	push(@output1,$value." ".$hsrc_port{$value});
}

my $nuofentries = scalar(@output1);
my $lastid = $nuofentries-1;
my $firstnid = 0;
if ($nuofentries > $maxlistlength) {
	$firstnid = $nuofentries-$maxlistlength;
}

for my $counter ($firstnid..$lastid) {
	my @src_port_sorted = split (' ', $output1[$counter]);
	printf("%-20s %-6s\n","\t".$src_port_sorted[0],$src_port_sorted[1]);
}
print "\n";

# 3. Destination port top list:
####################################################################################
print "\t--------------------------------------\n";
print "             Top ",$maxlistlength," Destination-Ports\n";
print "\t--------------------------------------\n";
print "\n";
printf("%-20s %-6s\n", "\tPort","Count");
print "\t--------------------------------------------------------------------------\n";
print "\n";

my %hdst_port; 
map { $hdst_port{$_}++ } @dst_port;
my @output1;

foreach my $value (sort {$hdst_port{$a} <=> $hdst_port{$b} } keys %hdst_port) {
	push(@output1,$value." ".$hdst_port{$value});
}

my $nuofentries = scalar(@output1);
my $lastid = $nuofentries-1;
my $firstnid = 0;
if ($nuofentries > $maxlistlength) {
	$firstnid = $nuofentries-$maxlistlength;
}

for my $counter ($firstnid..$lastid) {
	my @dst_port_sorted = split (' ', $output1[$counter]);
	printf("%-20s %-6s\n","\t".$dst_port_sorted[0],$dst_port_sorted[1]);
}
print "\n";

#4. Source IP top list:
####################################################################################
print "\t--------------------------------------\n";
print "                 Top ",$maxlistlength," IP Source\n";
print "\t--------------------------------------\n";
print "\n";
printf("%-40s %-20s %-6s\n", "\tdns name","IP","Count");
print "\t--------------------------------------------------------------------------\n";
print "\n";

my %hsrc_ip; 
map { $hsrc_ip{$_}++ } @src_ip;
my @output1;

foreach my $value (sort {$hsrc_ip{$a} <=> $hsrc_ip{$b} } keys %hsrc_ip) {
	push(@output1,$value." ".$hsrc_ip{$value});
}

my $nuofentries = scalar(@output1);
my $lastid = $nuofentries-1;
my $firstnid = 0;
if ($nuofentries > $maxlistlength) {
	$firstnid = $nuofentries-$maxlistlength;
}

for my $counter ($firstnid..$lastid) {
	my @src_ip_sorted = split (' ', $output1[$counter]);
	my $arecord  = nslookup(host => $src_ip_sorted[0], type => "PTR", timeout => 1);
	if ($arecord eq '') {
		printf("%-40s %-20s %-6s\n","\tnot in dns",$src_ip_sorted[0],$src_ip_sorted[1]);
	}
	else {
		printf("%-40s %-20s %-6s\n","\t".$arecord,$src_ip_sorted[0],$src_ip_sorted[1]);
	}
}
print "\n";

# 5. Destination IP top list:
####################################################################################
print "\t--------------------------------------\n";
print "              Top ",$maxlistlength," IP Destinations\n";
print "\t--------------------------------------\n";
print "\n";
printf("%-40s %-20s %-6s\n", "\tdns name","IP","Count");
print "\t--------------------------------------------------------------------------\n";
print "\n";

my %hdst_ip; 
map { $hdst_ip{$_}++ } @dst_ip;
my @output1;

foreach my $value (sort {$hdst_ip{$a} <=> $hdst_ip{$b} } keys %hdst_ip) {
	push(@output1,$value." ".$hdst_ip{$value});
}

my $nuofentries = scalar(@output1);
my $lastid = $nuofentries-1;
my $firstnid = 0;
if ($nuofentries > $maxlistlength) {
	$firstnid = $nuofentries-$maxlistlength;
}

for my $counter ($firstnid..$lastid) {
	my @dst_ip_sorted = split (' ', $output1[$counter]);
	my $arecord  = nslookup(host => $dst_ip_sorted[0], type => "PTR", timeout => 1);
	if ($arecord eq '') {
		printf("%-40s %-20s %-6s\n","\tnot in dns",$dst_ip_sorted[0],$dst_ip_sorted[1]);
	}
	else {
		printf("%-40s %-20s %-6s\n","\t".$arecord,$dst_ip_sorted[0],$dst_ip_sorted[1]);
	}
}
print "\n";

# 6. Destination IP with Port top list:
####################################################################################
print "\t--------------------------------------\n";
print "          Top ",$maxlistlength," IP Destinations with ports\n";
print "\t--------------------------------------\n";
print "\n";
printf("%-40s %-25s %-6s\n", "\tdns name","IP:Port","Count");
print "\t--------------------------------------------------------------------------\n";
print "\n";

my %hdst_ip_port; 
map { $hdst_ip_port{$_}++ } @dst_ip_port;
my @output1;

foreach my $value (sort {$hdst_ip_port{$a} <=> $hdst_ip_port{$b} } keys %hdst_ip_port) {
	push(@output1,$value." ".$hdst_ip_port{$value});
}

my $nuofentries = scalar(@output1);
my $lastid = $nuofentries-1;
my $firstnid = 0;
if ($nuofentries > $maxlistlength) {
	$firstnid = $nuofentries-$maxlistlength;
}

for my $counter ($firstnid..$lastid) {
	my @dst_ip_port_sorted = split (' ', $output1[$counter]);
	my @dst_ip_sorted = split (':', $dst_ip_port_sorted[0]);
	my $arecord  = nslookup(host => $dst_ip_sorted[0], type => "PTR", timeout => 1);
	if ($arecord eq '') {
		printf("%-40s %-25s %-6s\n", "\tnot in dns",$dst_ip_port_sorted[0],$dst_ip_port_sorted[1]);
	}
	else {
		printf("%-40s %-25s %-6s\n","\t".$arecord,$dst_ip_port_sorted[0],$dst_ip_port_sorted[1]);
	}
}
print "\n";