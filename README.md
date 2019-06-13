IBM Integration Bus Certification Expiration Monitor inspired on WAS (WebSphere Application Server) Certification Expiration Monitor (https://www.ibm.com/support/knowledgecenter/en/SS7K4U_9.0.0/com.ibm.websphere.zseries.doc/ae/csec_sslcertmonitoring.html)

# Setup

1. Create your test environment
1. Create a keystore with test certificates (you can use the JKS file provided in setup directory)
1. Configure your Integration Node or Integration Server:
```
BROKER=TESTNODE_tsuru
EG=default
CLONED_DIR=/GIT/iib-security-monitor

mqsichangeproperties $BROKER -e $EG -o ComIbmJVMManager -n keystoreFile -v $CLONED_DIR/setup/keystore_aug2019.jks
mqsichangeproperties $BROKER -e $EG -o ComIbmJVMManager -n keystorePass -v integration_server::keystorePass
mqsichangeproperties $BROKER -e $EG -o ComIbmJVMManager -n keystoreType -v JKS
mqsisetdbparms $BROKER -n integration_server::keystorePass -u na -p changeit
```
