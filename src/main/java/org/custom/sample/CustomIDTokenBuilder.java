/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 Inc. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein is strictly forbidden, unless permitted by WSO2 in accordance with
 * the WSO2 Commercial License available at http://wso2.com/licenses. For specific
 * language governing the permissions and limitations under this license,
 * please see the license as well as any agreement you’ve entered into with
 * WSO2 governing the purchase of this software and any associated services.
 */

package org.custom.sample;


import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.openidconnect.DefaultIDTokenBuilder;

import java.security.Key;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;


public class CustomIDTokenBuilder extends DefaultIDTokenBuilder{

    private static final Log log = LogFactory.getLog(CustomIDTokenBuilder.class);
    private static Map<Integer, Key> privateKeys = new ConcurrentHashMap<>();
    private OAuthServerConfiguration config = null;
    private Algorithm signatureAlgorithm = null;

    public CustomIDTokenBuilder() throws IdentityOAuth2Exception {
        config = OAuthServerConfiguration.getInstance();
        signatureAlgorithm = mapSignatureAlgorithm(config.getSignatureAlgorithm());
    }

    @Override
    protected String signJWTWithRSA(JWTClaimsSet jwtClaimsSet, OAuthTokenReqMessageContext request)
            throws IdentityOAuth2Exception {

        try {

            String tenantDomain = request.getAuthorizedUser().getTenantDomain();
            String clientId=request.getOauth2AccessTokenReqDTO().getClientId();
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

            Key privateKey;

            if (!(privateKeys.containsKey(tenantId))) {
                // get tenant's key store manager
                KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);

                if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {

                    //call the service by passing clientId and obtain the keystore
                    KeyStoreInfo keyStoreInfo=selectKeyStore(clientId);
                    String jksName = keyStoreInfo.getKeyStoreName();
                    privateKey = tenantKSM.getPrivateKey(jksName, tenantDomain);

                } else {
                    try {
                        privateKey = generatePrivateKeyforSuperTenant(tenantId,clientId);
                    } catch (Exception e) {
                        throw new IdentityOAuth2Exception("Error while obtaining private key for super tenant", e);
                    }
                }
                //privateKey will not be null always
                privateKeys.put(tenantId, privateKey);
            } else {
                //privateKey will not be null because containsKey() true says given key is exist and ConcurrentHashMap
                // does not allow to store null values
                privateKey = privateKeys.get(tenantId);
            }
            JWSSigner signer = new RSASSASigner((RSAPrivateKey) privateKey);
            SignedJWT signedJWT = new SignedJWT(new JWSHeader((JWSAlgorithm) signatureAlgorithm), jwtClaimsSet);
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new IdentityOAuth2Exception("Error occurred while signing JWT", e);
        }

    }
    /**
     * Method that returns the Keystore information.
     * @param clientId
     * @return Keystore information
     * your logic selecting keystore by passing client ID goes here.
     */

    private KeyStoreInfo selectKeyStore(String clientId) {
        log.info("calling the service to select the keystore");
        KeyStoreInfo keyStoreInfo=new KeyStoreInfo();
        keyStoreInfo.setKeyStoreName("wso2carbonold.jks");
        keyStoreInfo.setKeyStorePassword("wso2carbonold");
        keyStoreInfo.setKeyStoreAlias("wso2carbonold");
        return keyStoreInfo;
    }

    /**
     * Method that returns the private key.
     * @param tenantId
     * @param clientID
     * @return PrivateKey
     *
     */

    private PrivateKey generatePrivateKeyforSuperTenant(int tenantId,String clientID) throws Exception {
        KeyStoreInfo keyStoreInfo=selectKeyStore(clientID);
        String password =keyStoreInfo.getKeyStorePassword();
        String alias = keyStoreInfo.getKeyStoreAlias();
        String keyStoreName= keyStoreInfo.getKeyStoreName();
        KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);
        return (PrivateKey) tenantKSM.getKeyStore(keyStoreName).getKey(alias,password.toCharArray());
    }
}
