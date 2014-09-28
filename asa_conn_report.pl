#!/usr/bin/perl
# Author: Akos Daniel daniel.akos77ATgmail.com
# Filename: asa-conn_report.pl
# Current Version: 0.1 beta
# Created: 30th of Aug 2013
# Last Changed: 14th of Sept 2013
# -----------------------------------------------------------------------------------------------
# Description:
# -----------------------------------------------------------------------------------------------
# This is a rather crude and quick hacked Perl-script to create top list from 'sh conn all'
# output of the cisco asa firewall. It can count the following top lists:
# - Top Protocols
# - Top Source-Ports
# - Top Destination-Ports
# - Top IP Source
# - Top IP Destinations
# - Top IP Destinations with ports
#
# It can securely count only TCP and UDP sessions, for the other protocols it is not clear how to identify
# the source and the destination.
# Anyway this script assumes for not TCP and UDP sessions that the first ip:port is the source 
# and the next one is the destination in the output of the show conn command.
# -----------------------------------------------------------------------------------------------
# Known issues:
# - IGRP and GRE and 105(Cisco asa failover) protocols are not counted perfectly,
#   since the command "show conn" is not clear for source and destination.
# -----------------------------------------------------------------------------------------------
# - 
# -----------------------------------------------------------------------------------------------
# Change History
# -----------------------------------------------------------------------------------------------
# 0.1 beta: 30th of Aug 2013
#	- IP address lookup in DNS
# 	- Maximum number of the top list can be changed with the $maxlistlength variable. See below in the code
# 0.2 beta: 13th of Sept 2013
#	- The TCP and UDP session are better analysed, who the source and the destination is.
#	- The Identity as a source or destination is counted better.
#	- for all other protocols the script thinks the first ip is the source and the second one is the destination.
# 

use strict;
use Net::Netmask; # http://perltips.wikidot.com/module-net:netmask
use List::MoreUtils qw(uniq);
use Array::Utils qw(:all);
use Net::Nslookup;

# Set the maximum list count you wanna see. By default it is 7.
my $maxlistlength = 7;

# 1.) Open input-file and put the contents in one HUGE array
##################################################################################################

open (PARSEFILE,$ARGV[0]) || die ("==| Error! Could not open file $ARGV[0]"); # open the file to read

print "\nLoading ASA current session table from $ARGV[0]...\n";

my @Parse_array = <PARSEFILE>;
my $Parsefile_size = @Parse_array;
print "Done\n";

close (PARSEFILE);

# 2.) Save the source, destination ports and ips and source interface in arrays and variable
##################################################################################################

# The B Flag is used from "sh conn all" output.
# B initial SYN from outside 
# Link: http://www.cisco.com/en/US/docs/security/asa/asa82/command/reference/s2.html#wp1396672
#
# Example output from 'show conn':
# With B flag: (1. Source 2. Destination)
# TCP mydmz  172.23.27.4:4120 mydmz-priv  10.10.49.2:88, idle 0:03:21, bytes 9434, flags UIB
# Witout B flag: (1. Destination 2. Source)
# TCP suisse 10.8.178.2:383 inside 138.35.54.210:61838, idle 0:08:39, bytes 15156, flags UIO 
#
# For UDP the only way to define the source and the destination port is to check which port is above 1024.
# If the protocol UDP then check the port numbers and if only one is bigger as 1024 than we know how initiated the session.
# If the port numbers equal or both are above 1024 then we think the first ip is the source...
#
# For ICMP and other protocols we think the first ip is the source...
#

my @protocol;
my @src_iface;
my @src_ip;
my @src_ip_port;
my @src_port;
my @dst_iface;
my @dst_ip;
my @dst_ip_port;
my @dst_port;
my $equalportcount;
my $portabove1024count;

foreach my $line (@Parse_array) {
	if ($line =~ /^sh/) { # the line with the show command can be ignored.
		next;
	}
		
	# 1. First collect the ports and ips and interfaces in arrays.
	#    Here we do not check who is the source or destination
	#
	my @iface;
	my @ip;
	my @ip_data;
	my @ip_port;
	my @port;
	
	my @session = split (' ', $line);
	push(@protocol,$session[0]);
	push(@iface,$session[1]);
	if ($session[2] =~ /:/m) {
		push(@ip_port,$session[2]);
		# Split the IPs and Ports in a dedicated array
		my @ip_data = split (':', $session[2]);
		push(@ip,$ip_data[0]);
		push(@port,$ip_data[1]);
	}
	else {
		push(@ip_port,$session[2].':no_port');
		# Split the IPs and Ports in a dedicated array
		push(@ip,$session[2]);
		push(@port,'no_port');
	}
	push(@iface,$session[3]); # it can be 'NP' as well in case of 'Identity' as IP!
	# if IP_Port is 'Identity' only then there is no port. If no port given in output write 'no_port'
	# Examples:
	# UDP outside 145.1.1.1:500 NP Identity Ifc  1.1.1.1:500, idle 0:01:34, bytes 420, flags -
	# ESP outside 145.1.1.1 NP Identity Ifc  1.1.1.1, idle 0:00:01, bytes 188660, flags
	#
	if ($session[4] eq 'Identity') {
		if ($session[6] =~ /:/m) {
			my $field6 = $session[6]; # need to delete the colon in output
			$field6 =~ s/,//;
			my @field6 = split (':', $field6);
			push(@ip,'Identity_'.$field6[0]);
			push(@port,$field6[1]);
			push(@ip_port,'Identity_'.$field6[0].':'.$field6[1]);
		}
		else {
			my $field6 = $session[6]; # need to delete the colon in output
			$field6 =~ s/,//;
			push(@ip,'Identity_'.$field6);
			push(@port,'no_port');
			push(@ip_port,'Identity_'.$field6.':no_port');
		}
	}
	else {
		my $field4 = $session[4]; # need to delete the colon in output
		$field4 =~ s/,//;
		push(@ip_port,$field4);
		my @ip_data = split (':', $field4);
		push(@ip,$ip_data[0]);
		push(@port,$ip_data[1]);
	}
	
	# 2. Next start to check who is the source and the destination
	#
	if ($session[0] eq 'TCP' ) {
		# checking the B flag in session entry. IF B is there this is a backward session from lower level to higher level IF.
		if ($line =~ /flags\s.*B/) {
			push(@src_iface,$iface[0]);
			push(@src_ip_port,$ip_port[0]);
			push(@src_ip,$ip[0]);
			push(@src_port,$port[0]);
			push(@dst_iface,$iface[1]);
			push(@dst_ip_port,$ip_port[1]);
			push(@dst_ip,$ip[1]);
			push(@dst_port,$port[1]);
		}
		# If B Flag is not in session entry it is a normal way session (higher sec-level IF to lower sec-level IF)
		else {
			push(@src_iface,$iface[1]);
			push(@src_ip_port,$ip_port[1]);
			push(@src_ip,$ip[1]);
			push(@src_port,$port[1]);
			push(@dst_iface,$iface[0]);
			push(@dst_ip_port,$ip_port[0]);
			push(@dst_ip,$ip[0]);
			push(@dst_port,$port[0]);
		}
	} # end if statement for TCP Protocol
	elsif ($session[0] eq 'UDP' ) {
		
		# if they are equal, then we got talents! Good luck
		if ($port[0] eq $port[1]) {
			$equalportcount++;
			push(@src_iface,$iface[0]);
			push(@src_ip_port,$ip_port[0]);
			push(@src_ip,$ip[0]);
			push(@src_port,$port[0]);
			push(@dst_iface,$iface[1]);
			push(@dst_ip_port,$ip_port[1]);
			push(@dst_ip,$ip[1]);
			push(@dst_port,$port[1]);
		}
		# if they are larger than 1024, then we got talents! Good luck
		elsif ($port[0] > 1024 && $port[1]> 1024 ) {
			$portabove1024count++;
			push(@src_iface,$iface[0]);
			push(@src_ip_port,$ip_port[0]);
			push(@src_ip,$ip[0]);
			push(@src_port,$port[0]);
			push(@dst_iface,$iface[1]);
			push(@dst_ip_port,$ip_port[1]);
			push(@dst_ip,$ip[1]);
			push(@dst_port,$port[1]);
		}
		# I say the larger port is the source.
		elsif ($port[0] > $port[1]) {
			push(@src_iface,$iface[0]);
			push(@src_ip_port,$ip_port[0]);
			push(@src_ip,$ip[0]);
			push(@src_port,$port[0]);
			push(@dst_iface,$iface[1]);
			push(@dst_ip_port,$ip_port[1]);
			push(@dst_ip,$ip[1]);
			push(@dst_port,$port[1]);
		}
		else {
			push(@src_iface,$iface[1]);
			push(@src_ip_port,$ip_port[1]);
			push(@src_ip,$ip[1]);
			push(@src_port,$port[1]);
			push(@dst_iface,$iface[0]);
			push(@dst_ip_port,$ip_port[0]);
			push(@dst_ip,$ip[0]);
			push(@dst_port,$port[0]);
		}
	}
	# If not TCP or UDP we put it as it is...
	else {
		push(@src_iface,$iface[0]);
		push(@src_ip_port,$ip_port[0]);
		push(@src_ip,$ip[0]);
		push(@src_port,$port[0]);
		push(@dst_iface,$iface[1]);
		push(@dst_ip_port,$ip_port[1]);
		push(@dst_ip,$ip[1]);
		push(@dst_port,$port[1]);
	}
		
} # end foreach
print "\n";
print "\n";
print "\t---------------------------------------------------------------------------------------\n";
print "\tThe number of sessions not clear for the script(not clear who the src and the dst is.):\n";
print "\tNumber of equal portnumbers:  ",$equalportcount,"\n";
print "\tNumber of both portnumbers above 1024:  ",$portabove1024count,"\n";
print "\t---------------------------------------------------------------------------------------\n";
print "\n";

# 3. Protocol list:
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

# 4. Source port top list:
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

# 5. Destination port top list:
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

#6. Source IP top list:
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

# 7. Destination IP top list:
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

# 8. Destination IP with Port top list:
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