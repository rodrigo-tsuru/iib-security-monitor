IBM Integration Bus Certification Expiration Monitor inspired on WAS (WebSphere Application Server) Certification Expiration Monitor (https://www.ibm.com/support/knowledgecenter/en/SS7K4U_9.0.0/com.ibm.websphere.zseries.doc/ae/csec_sslcertmonitoring.html)

# Setup

#!/bin/bash
#https://www.ibm.com/support/knowledgecenter/pt-br/SSMKHH_10.0.0/com.ibm.etools.mft.doc/ac56640_.htm
BROKER=TESTNODE_tsuru
EG=default
CLONED_DIR=/GIT/iib-security-monitor

mqsichangeproperties $BROKER -e $EG -o ComIbmJVMManager -n keystoreFile -v $CLONED_DIR/setup/keystore_aug2019.jks
mqsichangeproperties $BROKER -e $EG -o ComIbmJVMManager -n keystorePass -v integration_server::keystorePass
mqsichangeproperties $BROKER -e $EG -o ComIbmJVMManager -n keystoreType -v JKS
mqsisetdbparms $BROKER -n integration_server::keystorePass -u na -p changeit
