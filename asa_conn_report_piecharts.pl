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
use SVG::TT::Graph::Pie; # for piechart
use Image::Magick; # to convert svg to png

# Set the maximum list count you wanna see. By default it is 7.
my $maxlistlength = 7;

# 1.) Open input-file and put the contents in one HUGE array
##################################################################################################

open (PARSEFILE,$ARGV[0]) || die ("==| Error! Could not open file $ARGV[0]"); # open the file to read

my @Parse_array = <PARSEFILE>;
my $Parsefile_size = @Parse_array;

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

# 3. Protocol list:
####################################################################################

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

my @protocolnames;
my @protocolcounts;

for my $counter ($firstnid..$lastid) {
	my @protocol_sorted = split (' ', $output1[$counter]);
	push (@protocolnames, $protocol_sorted[0]);
	push (@protocolcounts, $protocol_sorted[1]);
}

# create pie chart in svg for protocols

my $graph = SVG::TT::Graph::Pie->new({
		'height' => '500',
		'width'  => '900',
		'fields' => \@protocolnames,
		'show_graph_title' => 1,
		'graph_title' => 'Protocols',
		'show_shadow' => 1,
		'shadow_size' => 1,
		'shadow_offset' => 15,
		'show_percent' => 1,
		'key' => 1,
		#'key_placement' => 'T',
		'show_key_data_labels' => 1,
		'show_key_percent' => 1,
		'expand_greatest' => 1,
		'show_key_actual_values' => 0, # default is 1
});
  
$graph->add_data({
		'data'  => \@protocolcounts,
		'title' => 'Protocols',
});

# example from input filename:
# sh_conn_all_asa-rzsvc-wa.media-saturn.com.txt
my $hostname = $ARGV[0];
$hostname =~ s/sh_conn_all_//;
$hostname =~ s/\.txt//;
my $filename = $hostname."_piechart_protocol.png";

open STDOUT, '>', "piechart_protocol.svg";
print $graph->burn();

# convert svg to png
my $p;
$p = new Image::Magick;
$p->Read("piechart_protocol.svg");
$p->Set(density => 144, background => 'none');

$p->Trim;
$p->Write($filename);

# 4. Source port top list:
####################################################################################

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

my @src_ports;
my @src_portscounts;

for my $counter ($firstnid..$lastid) {
	my @src_port_sorted = split (' ', $output1[$counter]);
	push (@src_ports, $src_port_sorted[0]);
	push (@src_portscounts, $src_port_sorted[1]);
}

# create pie chart in svg for protocols

my $graph = SVG::TT::Graph::Pie->new({
		'height' => '500',
		'width'  => '900',
		'fields' => \@src_ports,
		'show_graph_title' => 1,
		'graph_title' => 'Source Ports',
		'show_shadow' => 1,
		'shadow_size' => 1,
		'shadow_offset' => 15,
		'show_percent' => 1,
		'key' => 1,
		#'key_placement' => 'T',
		'show_key_data_labels' => 1,
		'show_key_percent' => 1,
		'expand_greatest' => 1,
		'show_key_actual_values' => 0, # default is 1
});
  
$graph->add_data({
		'data'  => \@src_portscounts,
		'title' => 'Source ports',
});

open STDOUT, '>', "piechart_src_port.svg";
print $graph->burn();

# convert svg to png
my $filename = $hostname."_piechart_src_port.png";

my $p;
$p = new Image::Magick;
$p->Read("piechart_src_port.svg");
$p->Set(density => 144, background => 'none');

$p->Trim;
$p->Write($filename);

# 5. Destination port top list:
####################################################################################

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

my @dst_ports;
my @dst_portscounts;

for my $counter ($firstnid..$lastid) {
	my @dst_port_sorted = split (' ', $output1[$counter]);
	push (@dst_ports, $dst_port_sorted[0]);
	push (@dst_portscounts, $dst_port_sorted[1]);
}

# create pie chart in svg for protocols

my $graph = SVG::TT::Graph::Pie->new({
		'height' => '500',
		'width'  => '900',
		'fields' => \@dst_ports,
		'show_graph_title' => 1,
		'graph_title' => 'Destination Ports',
		'show_shadow' => 1,
		'shadow_size' => 1,
		'shadow_offset' => 15,
		'show_percent' => 1,
		'key' => 1,
		#'key_placement' => 'T',
		'show_key_data_labels' => 1,
		'show_key_percent' => 1,
		'expand_greatest' => 1,
		'show_key_actual_values' => 0, # default is 1
});
  
$graph->add_data({
		'data'  => \@dst_portscounts,
		'title' => 'Destination ports',
});

open STDOUT, '>', "piechart_dst_port.svg";
print $graph->burn();

# convert svg to png
my $filename = $hostname."_piechart_dst_port.png";

my $p;
$p = new Image::Magick;
$p->Read("piechart_dst_port.svg");
$p->Set(density => 144, background => 'none');

$p->Trim;
$p->Write($filename);

#6. Source IP top list:
####################################################################################

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

my @src_ips;
my @src_ipscounts;

for my $counter ($firstnid..$lastid) {
	my @src_ip_sorted = split (' ', $output1[$counter]);
	my $arecord  = nslookup(host => $src_ip_sorted[0], type => "PTR", timeout => 1);
	if ($arecord eq '') {
		push (@src_ips, $src_ip_sorted[0]);
	}
	else {
		push (@src_ips, $arecord);
	}
	push (@src_ipscounts, $src_ip_sorted[1]);
}

# create pie chart in svg for protocols

my $graph = SVG::TT::Graph::Pie->new({
		'height' => '500',
		'width'  => '900',
		'fields' => \@src_ips,
		'show_graph_title' => 1,
		'graph_title' => 'Source IPs',
		'show_shadow' => 1,
		'shadow_size' => 1,
		'shadow_offset' => 15,
		'show_percent' => 1,
		'key' => 1,
		#'key_placement' => 'T',
		'show_key_data_labels' => 1,
		'show_key_percent' => 1,
		'expand_greatest' => 1,
		'show_key_actual_values' => 0, # default is 1
});
  
$graph->add_data({
		'data'  => \@src_ipscounts,
		'title' => 'Source IPs',
});

open STDOUT, '>', "piechart_src_ip.svg";
print $graph->burn();

# convert svg to png
my $filename = $hostname."_piechart_src_ip.png";

my $p;
$p = new Image::Magick;
$p->Read("piechart_src_ip.svg");
$p->Set(density => 144, background => 'none');

$p->Trim;
$p->Write($filename);

# 7. Destination IP top list:
####################################################################################

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

my @dst_ips;
my @dst_ipscounts;

for my $counter ($firstnid..$lastid) {
	my @dst_ip_sorted = split (' ', $output1[$counter]);
	my $arecord  = nslookup(host => $dst_ip_sorted[0], type => "PTR", timeout => 1);
	if ($arecord eq '') {
		push (@dst_ips, $dst_ip_sorted[0]);
	}
	else {
		push (@dst_ips, $arecord);
	}
	push (@dst_ipscounts, $dst_ip_sorted[1]);
}

# create pie chart in svg for protocols

my $graph = SVG::TT::Graph::Pie->new({
		'height' => '500',
		'width'  => '900',
		'fields' => \@dst_ips,
		'show_graph_title' => 1,
		'graph_title' => 'Destination IPs',
		'show_shadow' => 1,
		'shadow_size' => 1,
		'shadow_offset' => 15,
		'show_percent' => 1,
		'key' => 1,
		#'key_placement' => 'T',
		'show_key_data_labels' => 1,
		'show_key_percent' => 1,
		'expand_greatest' => 1,
		'show_key_actual_values' => 0, # default is 1
});
  
$graph->add_data({
		'data'  => \@dst_ipscounts,
		'title' => 'Destination IPs',
});

open STDOUT, '>', "piechart_dst_ip.svg";
print $graph->burn();

# convert svg to png
my $filename = $hostname."_piechart_dst_ip.png";

my $p;
$p = new Image::Magick;
$p->Read("piechart_dst_ip.svg");
$p->Set(density => 144, background => 'none');

$p->Trim;
$p->Write($filename);

# 8. Destination IP with Port top list:
####################################################################################

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

my @dst_ip_ports;
my @dst_ip_portscounts;

for my $counter ($firstnid..$lastid) {
	my @dst_ip_port_sorted = split (' ', $output1[$counter]);
	my @dst_ip_sorted = split (':', $dst_ip_port_sorted[0]);
	my $arecord  = nslookup(host => $dst_ip_sorted[0], type => "PTR", timeout => 1);
	if ($arecord eq '') {
		push (@dst_ip_ports, $dst_ip_port_sorted[0]);
	}
	else {
		push (@dst_ip_ports, $arecord." ".$dst_ip_sorted[1]);
	}
	push (@dst_ip_portscounts, $dst_ip_port_sorted[1]);
}

# create pie chart in svg for protocols

my $graph = SVG::TT::Graph::Pie->new({
		'height' => '500',
		'width'  => '900',
		'fields' => \@dst_ip_ports,
		'show_graph_title' => 1,
		'graph_title' => 'Destination IPs with Ports',
		'show_shadow' => 1,
		'shadow_size' => 1,
		'shadow_offset' => 15,
		'show_percent' => 1,
		'key' => 1,
		#'key_placement' => 'T',
		'show_key_data_labels' => 1,
		'show_key_percent' => 1,
		'expand_greatest' => 1,
		'show_key_actual_values' => 0, # default is 1
});
  
$graph->add_data({
		'data'  => \@dst_ip_portscounts,
		'title' => 'Destination IPs with Ports',
});

open STDOUT, '>', "piechart_dst_ip_port.svg";
print $graph->burn();

# convert svg to png
my $filename = $hostname."_piechart_dst_ip_port.png";

my $p;
$p = new Image::Magick;
$p->Read("piechart_dst_ip_port.svg");
$p->Set(density => 144, background => 'none');

$p->Trim;
$p->Write($filename);