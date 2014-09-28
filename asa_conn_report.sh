#!/bin/bash
# Author: Akos Daniel daniel.akos77ATgmail.com
# Filename: asa_conn_report.sh
# Current Version: 0.1 Beta
# Created: 2nd of Feb 2014
# Last Changed: 2nd of Feb 2014
# -----------------------------------------------------------------------------------------------
# Description:
# -----------------------------------------------------------------------------------------------
# This script is a real poor man solution to get connection report from cisco asa in a given time.
# This scripts input is the output of sh conn all command.
#
# -----------------------------------------------------------------------------------------------
# Known issues:
# 
# -----------------------------------------------------------------------------------------------
# Solved Issues:
#
# -----------------------------------------------------------------------------------------------
# Change History:
# 0.1 beta: (2nd of Feb 2014)
# 
# -----------------------------------------------------------------------------------------------

# $1 is the first argument, the input file.
# The B Flag is not used!!! from sh conn output...
# B initial SYN from outside 
# http://www.cisco.com/en/US/docs/security/asa/asa82/command/reference/s2.html#wp1396672

# 1. Protocol top list:
echo "      --------------------------------------"
echo "                 Top 7 Protocols"
echo "      --------------------------------------"
echo ""
awk '{print $1}' $1 | grep -v sh | sort | uniq -c | sort -n | awk '{print "      ",$1,$2}' | tail -n 7
echo ""

# 2. Port1 top list:
echo "      --------------------------------------"
echo "               Top 7 Source-Ports"
echo "      -------------------------------------"
echo ""
awk '{print $3,$1}' $1 | awk -F":" '{print $2}' | sort | uniq -c | sort -n | awk '{print "      ",$1,$2}' | tail -n 7
echo ""

# 3. Port2 top list (Destination port?):
echo "      --------------------------------------"
echo "             Top 7 Destination-Ports"
echo "      --------------------------------------"
echo ""
awk '{print $5,$1}' $1 | awk -F":" '{print $2}' | sort | uniq -c | sort -n | awk '{print "      ",$1,$2}' | tail -n 7
echo ""

#4. IP1 top list (Source):
echo "      --------------------------------------"
echo "                 Top 7 IP Source"
echo "      --------------------------------------"
echo ""
awk '{print $3}' $1 | awk -F":" '{print $1}' | sort | uniq -c | sort -n | awk '{print "      ",$1,$2}' | tail -n 7
echo ""

# 5. IP2 top list (Destination):
echo "      --------------------------------------"
echo "              Top 7 IP Destinations"
echo "      --------------------------------------"
echo ""
awk '{print $5}' $1 | awk -F":" '{print $1}' | sort | uniq -c | sort -n | awk '{print "      ",$1,$2}' | tail -n 7
echo ""

# 6. IP2 with Port top list (Destination):
echo "      --------------------------------------"
echo "          Top 7 IP Destinations with ports"
echo "      --------------------------------------"
echo ""
awk '{print $5}' $1 | sort | uniq -c | sort -n | awk '{print "      ",$1,$2}' | tail -n 7