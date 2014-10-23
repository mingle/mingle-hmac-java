package com.thoughtworks.mingle.api.hmac;

import com.dephillipsdesign.logomatic.LogOMatic;
import com.dephillipsdesign.logomatic.Logger;
import com.google.common.base.Joiner;
import com.thoughtworks.mingle.api.hmac.HmacAuth;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.protocol.HttpContext;

import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.TimeZone;

public class HmacRequestInterceptor implements HttpRequestInterceptor {

    private static final DateFormat RFC_1123_DATE_TIME_FORMAT;
    static {
        RFC_1123_DATE_TIME_FORMAT = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss zzz");
        RFC_1123_DATE_TIME_FORMAT.setTimeZone(TimeZone.getTimeZone("GMT"));
    }
    private final HmacAuth auth;

    private static final Logger log = LogOMatic.getLogger(HmacRequestInterceptor.class);

    public HmacRequestInterceptor(HmacAuth auth) {
        this.auth = auth;
    }

    @Override
    public void process(HttpRequest httpRequest, HttpContext ctx) throws HttpException, IOException {
        //canonical_string = 'content-type,content-MD5,request URI,timestamp'
        String uri = httpRequest.getRequestLine().getUri();

        Date date = ctx.getAttribute("fakeTestingTimestamp") == null ? new Date() : (Date) ctx.getAttribute("fakeTestingTimestamp");
        String timestamp = RFC_1123_DATE_TIME_FORMAT.format(date);

        String canonical = Joiner.on(",").join(Arrays.asList("", "", uri, timestamp));

        // Base64 encoded SHA1 HMAC, using the client's private secret key
        String hmac = auth.signCanonicalString(canonical);

        log.debugf("HMAC Auth Header '%s' set for %s", hmac, uri);
        // Authorization = APIAuth 'client access id':'signature from step 2'
        String headerValue = String.format("APIAuth %s:%s", auth.getLogin(), hmac);
        httpRequest.setHeader("Authorization", headerValue);
        httpRequest.setHeader("Date", timestamp);
    }

}
