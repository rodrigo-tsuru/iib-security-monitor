#!/bin/bash
#https://www.ibm.com/support/knowledgecenter/pt-br/SSMKHH_10.0.0/com.ibm.etools.mft.doc/ac56640_.htm
BROKER=TESTNODE_tsuru
EG=default
mqsichangeproperties $BROKER -e $EG -o ComIbmJVMManager -n keystoreFile -v /home/tsuru/GIT/iib-security-monitor/keystore_ago2019.jks
mqsichangeproperties $BROKER -e $EG -o ComIbmJVMManager -n keystorePass -v integration_server::keystorePass
mqsichangeproperties $BROKER -e $EG -o ComIbmJVMManager -n keystoreType -v JKS
mqsisetdbparms $BROKER -n integration_server::keystorePass -u na -p changeit
