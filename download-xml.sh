#!/bin/sh

# download files that we need
/usr/bin/wget -N "https://www.redhat.com/security/data/oval/com.redhat.rhsa-all.xml"
/usr/bin/wget -N "https://www.redhat.com/security/data/metrics/rpm-to-cve.xml"

