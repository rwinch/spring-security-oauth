package org.springframework.security.oauth2.common;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

import java.io.IOException;
import java.util.Date;
import java.util.Set;
import java.util.TreeSet;

import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PrepareForTest({System.class,OAuth2AccessTokenJsonSerializer.class,OAuth2AccessTokenJsonDeserializer.class})
public class TestOAuth2AccessTokenJsonSerializer {
    @Rule
    public ExpectedException thrown = ExpectedException.none();
    @Mock
    private Date expiration;

    private static final String ACCESS_TOKEN_MULTISCOPE = "{\"access_token\":\"token-value\",\"expired\":false,\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":10,\"scope\":\"read write\"}";
    private OAuth2AccessToken accessToken;
    private ObjectMapper mapper;

    @Before
    public void setUp() {
        mockStatic(System.class);
        long now = 1323123715041L;
        when(System.currentTimeMillis()).thenReturn(now);
        when(expiration.before(any(Date.class))).thenReturn(false);
        when(expiration.getTime()).thenReturn(now+10000);

        accessToken = new OAuth2AccessToken("token-value");
        accessToken.setExpiration(expiration);
        mapper = new ObjectMapper();
        OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-value");
        accessToken.setRefreshToken(refreshToken);
        Set<String> scope = new TreeSet<String>();
        scope.add("read");
        scope.add("write");
        accessToken.setScope(scope);
    }

    @Test
    public void serializeNoRefresh() throws JsonGenerationException, JsonMappingException, IOException {
        accessToken.setRefreshToken(null);
        accessToken.setScope(null);
        String encodedAccessToken = mapper.writeValueAsString(accessToken);
        assertEquals("{\"access_token\":\"token-value\",\"expired\":false,\"token_type\":\"bearer\",\"expires_in\":10}",encodedAccessToken);
    }

    @Test
    public void serializeWithRefresh() throws JsonGenerationException, JsonMappingException, IOException {
        accessToken.setScope(null);
        String encodedAccessToken = mapper.writeValueAsString(accessToken);
        assertEquals("{\"access_token\":\"token-value\",\"expired\":false,\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":10}",encodedAccessToken);
    }

    @Test
    public void serializeWithEmptyScope() throws JsonGenerationException, JsonMappingException, IOException {
        accessToken.getScope().clear();
        String encodedAccessToken = mapper.writeValueAsString(accessToken);
        assertEquals("{\"access_token\":\"token-value\",\"expired\":false,\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":10}",encodedAccessToken);
    }

    @Test
    public void serializeWithSingleScopes() throws JsonGenerationException, JsonMappingException, IOException {
        accessToken.getScope().remove(accessToken.getScope().iterator().next());
        String encodedAccessToken = mapper.writeValueAsString(accessToken);
        assertEquals("{\"access_token\":\"token-value\",\"expired\":false,\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":10,\"scope\":\"write\"}",encodedAccessToken);
    }

    @Test
    public void serializeWithNullScope() throws JsonGenerationException, JsonMappingException, IOException {
        thrown.expect(JsonMappingException.class);
        thrown.expectMessage("Scopes cannot be null or empty. Got [null]");
        accessToken.getScope().clear();
        accessToken.getScope().add(null);
        mapper.writeValueAsString(accessToken);
    }

    @Test
    public void serializeWithEmptyStringScope() throws JsonGenerationException, JsonMappingException, IOException {
        thrown.expect(JsonMappingException.class);
        thrown.expectMessage("Scopes cannot be null or empty. Got []");
        accessToken.getScope().clear();
        accessToken.getScope().add("");
        String encodedAccessToken = mapper.writeValueAsString(accessToken);
        assertEquals("{\"access_token\":\"token-value\",\"expired\":false,\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":10,\"scope\":\"\"}",encodedAccessToken);
    }

    @Test
    public void serializeWithMultiScopes() throws JsonGenerationException, JsonMappingException, IOException {
        String encodedAccessToken = mapper.writeValueAsString(accessToken);
        assertEquals(ACCESS_TOKEN_MULTISCOPE,encodedAccessToken);
    }

    @Test
    public void deserializeWithMultiScopes() throws Exception {
        OAuth2AccessToken actual = mapper.readValue(ACCESS_TOKEN_MULTISCOPE, OAuth2AccessToken.class);
        assertTokenEquals(actual,accessToken);
    }

    private static void assertTokenEquals(OAuth2AccessToken expected, OAuth2AccessToken actual) {
        assertEquals(expected.getTokenType(),actual.getTokenType());
        assertEquals(expected.getValue(),actual.getValue());

        OAuth2RefreshToken expectedRefreshToken = expected.getRefreshToken();
        if(expectedRefreshToken == null) {
            assertNull(actual.getRefreshToken());
        } else {
            assertEquals(expectedRefreshToken.getValue(),actual.getRefreshToken().getValue());
        }
        assertEquals(expected.getScope(),actual.getScope());
        Date expectedExpiration = expected.getExpiration();
        if(expectedExpiration == null) {
            assertNull(actual.getExpiration());
        } else {
            assertEquals(expectedExpiration.getTime(),actual.getExpiration().getTime());
        }
    }
}
