#!/usr/bin/perl

#
# SecurityGuy 2017.04.25
#

use strict;
use warnings;

# check if modules exist
eval { require XML::Simple; };
if ($@) { die "[*]: $0: ERROR: require module XML::Simple: can't load module $@\n on CentOS: yum install perl-XML-Simple";}

eval { require utf8; };
if ($@) { die "[*]: $0: ERROR: require module utf8: can't load module $@\n on CentOS: yum install perl-utf8-all";}

use XML::Simple;
use utf8;

#use Data::Dumper 'Dumper';

sub uniq {
  my (@input) = @_;
  my %all = ();
  @all{@input} = 1;
  return (keys %all);
}


# /usr/bin/wget -N "https://www.redhat.com/security/data/oval/com.redhat.rhsa-all.xml"
# /usr/bin/wget -N "https://www.redhat.com/security/data/metrics/rpm-to-cve.xml"

if ( ( ! -f "rpm-to-cve.xml" ) || ( ! -f "com.redhat.rhsa-all.xml" ) )
{
        die ("[*] $0: ERROR: cannot open file $!");
}

binmode(STDIN,  ':encoding(utf8)');
binmode(STDOUT, ':encoding(utf8)');
binmode(STDERR, ':encoding(utf8)');


#  force cve to be ARRAY
my $xmlrpm;
my $xmlrhsa;

# Open RPM xml, force cve to be array
if (not($xmlrpm = XMLin( 'rpm-to-cve.xml', ForceArray => ['cve'] )))
{
        die ("[*]: $0: ERROR: XMLin: Could not parse file: $!\n");
}
#print Dumper($xmlrpm);

# Open RHSA xml, force cve to be array
if (not($xmlrhsa = XMLin('com.redhat.rhsa-all.xml',ForceArray => [  'cve' ])))
{
        die ("[*]: $0: ERROR: XMLin: Could not parse file: $!\n");
}
#print Dumper($xmlrhsa);


# mem hashes
my ( %cve_list, %rpm_list ) = ();



# loop through all entries
foreach my $rhsa ( sort keys %{ $xmlrhsa->{definitions}->{definition} } )
{

        # define the entry
        my $entry = $xmlrhsa->{definitions}->{definition}->{$rhsa};

        # CVE info
        if (defined ($entry->{metadata}->{advisory}->{cve}))
        {
                foreach my $cve ( @{ $entry->{metadata}->{advisory}->{cve} })
                {
                        if ( (defined ( $cve->{content} )) && (defined ($cve->{cvss2})) )
                        {
                                next if ( $cve->{content} !~ m/^CVE/i );
                                my $cve_id   = $cve->{content};
                                my $score_id = $cve->{cvss2};
                                my ($score) = ($score_id =~ m{^(\d+(\.\d+)?)});
                                $cve_list{$cve_id} = $score;
                        }
                }
        }
}
#print Dumper (%cve_list);

foreach my $entry (@{$xmlrpm->{'rpm'}})
{
        # safety checks!
        next if (! defined($entry->{'cve'}) );
        next if (! defined($entry->{'rpm'}) );

        my $rpm_name = $entry->{'rpm'};

        #$rpm_list{"$rpm_name"} = [];

        foreach my $cve_num ( @{$entry->{'cve'}} )
        {
                #push (@cves, $cve_num);
                #if ( exists ( $cve_list{$cve_num}{score} ) )
                if ( exists ( $cve_list{$cve_num} ) )
                {
                        #print  "$rpm_name $cve_num " . $cve_list{$cve_num}{score} . "\n";
                        my %hash = ();
                        #%hash = ( cve => "$cve_num", score => $cve_list{$cve_num}{score} );
                        %hash = ( cve => "$cve_num", score => $cve_list{$cve_num} );
                        push ( @{ $rpm_list{"$rpm_name"} }, \%hash );
                }
        }

        # perhaps the vulnerability does not affect RHEL 6 ?
        #delete $rpm_list{"$rpm_name"} if ( scalar  @{ $rpm_list{"$rpm_name"} }  == 0 );
}

#print Dumper (%rpm_list);


# RPM LIST
my $rpm_cmd = "/bin/rpm -qa --qf '%{N}-%{epochnum}:%{V}-%{R}\n'";
# from lpvs-scan.pl: https://github.com/lwindolf/lpvs
my $packageList = `$rpm_cmd`;

my @packages = split/\n/, $packageList ;
@packages = &uniq(@packages);

# stats
my $counter_cve = 0;
my $counter_pkg = 0;
my $counter_highrisk = 0;

foreach my $pkg ( sort @packages )
{
         if ( exists ( $rpm_list{$pkg} ) )
         {
                 if ( scalar ( @{ $rpm_list{"$pkg"} } ) > 0)
                 {
                         print "\n=====  $pkg  =====\n";
                         my @vulns = sort @{ $rpm_list{"$pkg"} };
                         foreach my $item (@vulns)
                         {
                                 #print "$pkg " . $item->{cve} . " " . $item->{score} . "\n";
                                 printf "%-60s%-20s\n", $item->{cve}, $item->{score};
                                 $counter_cve++;
                                 $counter_highrisk++ if ( $item->{score} > 7);
                         }
                         #print Dumper ($rpm_list{$pkg});
                         $counter_pkg++;
                 }
         }
}


print "\n\nTOTAL RPM_PACKAGES " . scalar(@packages) . " VULN_PACKAGES " . $counter_pkg . " VULN_CVEs " . $counter_cve . " VULN_HIGHRISK " . $counter_highrisk . "\n\n";

