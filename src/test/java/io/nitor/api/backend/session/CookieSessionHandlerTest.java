/**
 * Copyright 2017 Nitor Creations Oy
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.nitor.api.backend.session;

import com.example.mockito.MockitoExtension;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.SocketAddress;
import io.vertx.ext.web.Cookie;
import io.vertx.ext.web.RoutingContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.Extensions;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;

import static io.netty.handler.codec.http.HttpHeaderNames.USER_AGENT;
import static io.nitor.api.backend.session.CookieSessionHandler.CTX_KEY;
import static java.time.Instant.now;
import static java.util.Collections.singleton;
import static java.util.Collections.singletonMap;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.aMapWithSize;
import static org.hamcrest.Matchers.both;
import static org.hamcrest.Matchers.hasEntry;
import static org.mockito.ArgumentCaptor.forClass;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@Extensions(@ExtendWith(MockitoExtension.class))
class CookieSessionHandlerTest {
    private CookieSessionHandler handler;
    private StatelessSession session;
    private ArgumentCaptor<StatelessSession> newSession = forClass(StatelessSession.class);

    @BeforeEach
    public void setup(@Mock RoutingContext ctx, @Mock HttpServerRequest request, @Mock CookieConverter cookieConverter,
                      @Mock Cookie cookie, @Mock SocketAddress remoteAddress) {
        handler = new CookieSessionHandler(new JsonObject().put("secretFile", "target/secret"), cookieConverter);
        when(ctx.request()).thenReturn(request);
        when(ctx.cookies()).thenReturn(singleton(cookie));
        when(request.remoteAddress()).thenReturn(remoteAddress);
        when(remoteAddress.host()).thenReturn("remoteIp");

        session = new StatelessSession();
        session.sessionData.put("test", "data");
    }

    @Test
    public void invalidSessionDataAlreadyInContext(@Mock RoutingContext ctx, @Mock StatelessSession session) {
        when(ctx.get(CTX_KEY)).thenReturn(session);
        assertThat(handler.getSessionData(ctx), nullValue());
    }

    @Test
    public void validSessionDataAlreadyInContext(@Mock RoutingContext ctx) {
        session.setValid(true);
        when(ctx.get(CTX_KEY)).thenReturn(session);
        assertThat(handler.getSessionData(ctx), sameInstance(session.sessionData));
    }

    @Test
    public void fetchesValidSessionFromCookie(@Mock RoutingContext ctx, @Mock HttpServerRequest request, @Mock CookieConverter cookieConverter) {
        when(request.getHeader(USER_AGENT)).thenReturn("Firefox 61");
        session.setContextData(null, "Firefox 0");
        session.setSourceIpSession("remoteIp", now().plusSeconds(300));
        when(cookieConverter.getSession(ctx.cookies())).thenReturn(session);
        assertThat(handler.getSessionData(ctx), sameInstance(session.sessionData));
        verify(ctx).put(CTX_KEY, session);
        assertThat(session.isValid(), is(true));
    }

    @Test
    public void fetchesSessionWithInvalidContextFromCookie(@Mock RoutingContext ctx, @Mock HttpServerRequest request, @Mock CookieConverter cookieConverter) {
        when(request.getHeader(USER_AGENT)).thenReturn("Firefox 61");
        session.setContextData("another server", "Firefox 0");
        session.setSourceIpSession("remoteIp", now().plusSeconds(300));
        when(cookieConverter.getSession(ctx.cookies())).thenReturn(session);
        assertThat(handler.getSessionData(ctx), nullValue());
        verify(ctx).put(eq(CTX_KEY), newSession.capture());
        assertThat(newSession.getValue().isValid(), is(false));
        assertThat(newSession.getValue().contextDataMatches(null, "Firefox 0"), is(true));
    }

    @Test
    void setSessionData(@Mock RoutingContext ctx, @Mock HttpServerRequest request, @Mock CookieConverter cookieConverter, @Mock Cookie cookie) {
        when(ctx.get(CTX_KEY)).thenReturn(session);
        when(cookieConverter.sessionToCookie(session)).thenReturn(cookie);
        session.setSourceIpSession("oldIp", now().plusSeconds(300));
        handler.setSessionData(ctx, singletonMap("newKey", "newValue"));
        assertThat(session.isValid(), is(true));
        assertThat(session.sessionData, both(aMapWithSize(1)).and(hasEntry("newKey", "newValue")));
        assertThat(session.hasSourceIpSession("oldIp"), is(true));
        assertThat(session.hasSourceIpSession("remoteIp"), is(true));
        verify(ctx).addCookie(cookie);
    }
}
