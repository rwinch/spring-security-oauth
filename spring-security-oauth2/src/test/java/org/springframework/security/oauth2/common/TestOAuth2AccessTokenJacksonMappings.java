package org.springframework.security.oauth2.common;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.Date;
import java.util.Set;
import java.util.TreeSet;

import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.Before;
import org.junit.Test;

public class TestOAuth2AccessTokenJacksonMappings {
    private static final String ACCESS_TOKEN_MULTISCOPE = "{\"value\":\"token-value\",\"expired\":false,\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":8,\"scope\":\"read write\"}";
    private OAuth2AccessToken accessToken;
    private ObjectMapper mapper;

    @Before
    public void setUp() {
        accessToken = new OAuth2AccessToken("token-value");
        accessToken.setExpiration(new Date(System.currentTimeMillis()+10000));
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
        assertEquals("{\"value\":\"token-value\",\"expired\":false,\"token_type\":\"bearer\",\"expires_in\":8}",encodedAccessToken);
    }

    @Test
    public void serializeWithRefresh() throws JsonGenerationException, JsonMappingException, IOException {
        accessToken.setScope(null);
        String encodedAccessToken = mapper.writeValueAsString(accessToken);
        assertEquals("{\"value\":\"token-value\",\"expired\":false,\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":8}",encodedAccessToken);
    }

    @Test
    public void serializeWithEmptyScope() throws JsonGenerationException, JsonMappingException, IOException {
        accessToken.getScope().clear();
        String encodedAccessToken = mapper.writeValueAsString(accessToken);
        assertEquals("{\"value\":\"token-value\",\"expired\":false,\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":8}",encodedAccessToken);
    }

    @Test
    public void serializeWithSingleScopes() throws JsonGenerationException, JsonMappingException, IOException {
        accessToken.getScope().remove(accessToken.getScope().iterator().next());
        String encodedAccessToken = mapper.writeValueAsString(accessToken);
        assertEquals("{\"value\":\"token-value\",\"expired\":false,\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":8,\"scope\":\"write\"}",encodedAccessToken);
    }

    @Test
    public void serializeWithMultiScopes() throws JsonGenerationException, JsonMappingException, IOException {
        String encodedAccessToken = mapper.writeValueAsString(accessToken);
        assertEquals(ACCESS_TOKEN_MULTISCOPE,encodedAccessToken);
    }

    @Test
    public void deserializeWithMultiScopes() throws Exception {
        OAuth2AccessToken actual = mapper.readValue(ACCESS_TOKEN_MULTISCOPE, OAuth2AccessToken.class);
        assertEquals(accessToken.getTokenType(),actual.getTokenType());
        assertEquals(accessToken.getValue(),actual.getValue());
        assertEquals(accessToken.getRefreshToken().getValue(),actual.getRefreshToken().getValue());
        assertEquals(accessToken.getScope(),actual.getScope());
        assertEquals(accessToken.getExpiration(),actual.getExpiration());
    }
}
