This CustomIDTokenBuilder will take the defined keystore information and do the sign process.
Applicable version IS 5.1.0

------------------------
Instructions
--------------------------

1.Modify and implement your logic in  the method  "private KeyStoreInfo selectKeyStore(String clientId)"
present in the CustomIDTokenBuilder java class to retrieve the Key store information by passing the  ClientID to your service which has the ability to mention the key store information to be used against the client ID.

2.Then build the SampleIDTokenBuilder project using command "mvn clean install".

3.Shutdown the server if already started.

3.Go to the target directory and copy the SampleIDTokenBuilder-1.0-SNAPSHOT.jar file to the
<IS_HOME>/repository/components/dropins directory.

4.Then open the file identity.xml file resides in the <IS_HOME>/repository/conf/identity folder.

5.Search the line "org.wso2.carbon.identity.openidconnect.DefaultIDTokenBuilder" and
 replace the it with "org.custom.sample.CustomIDTokenBuilder".

6.Then Restart the Server.

