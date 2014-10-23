package com.thoughtworks.mingle.api.hmac.hmac;

import com.thoughtworks.mingle.api.hmac.HmacAuth;
import com.thoughtworks.mingle.api.hmac.HmacRequestInterceptor;
import org.apache.http.Header;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.net.URI;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

public class HmacAuthTest {

    private static final DateFormat RFC_1123_DATE_TIME_FORMAT = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss Z");

    @Test
    public void shouldSignRequestCorrectly() throws IOException, HttpException, ParseException {
        String expectedHeaderValue = "APIAuth admin:mq5cubC7Dgja+OvmsFzcC5Eg/5w=";

        HttpRequest request = new HttpGet("/api/v2/projects/minglezy/murmurs.xml");
        HmacRequestInterceptor interceptor = new HmacRequestInterceptor(new HmacAuth("admin", "4QeLVQL/GrICAhReNZYHMeNzYNnPdmmrbCF4fqfNBs4="));
        HttpContext context = new BasicHttpContext();
        context.setAttribute("fakeTestingTimestamp", RFC_1123_DATE_TIME_FORMAT.parse("Wed, 22 Oct 2014 18:44:50 GMT"));

        interceptor.process(request, context);

        Header header = request.getHeaders("Authorization")[0];

        assertThat(header.getValue(), equalTo(expectedHeaderValue));
    }
}
