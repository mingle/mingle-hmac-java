package com.thoughtworks.mingle.api.hmac;

import com.dephillipsdesign.logomatic.LogOMatic;
import com.dephillipsdesign.logomatic.Logger;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;


public class HmacAuth {

    private final String login;
    private final String key;

    private static final Logger log = LogOMatic.getLogger(HmacAuth.class);

    public HmacAuth(String login, String key) {
        this.login = login;
        this.key = key;
    }

    public String getLogin() {
        return this.login;
    }

    public String signCanonicalString(String canonicalString) {
        try {
            log.debugf("HMAC signing request '%s' for %s", canonicalString, this.login);
            Mac mac = Mac.getInstance("HmacSHA1");
            SecretKeySpec secret = new SecretKeySpec(key.getBytes(), mac.getAlgorithm());
            mac.init(secret);
            byte[] digest = mac.doFinal(canonicalString.getBytes());
            byte[] result = Base64.encodeBase64(digest);
            return new String(result);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
