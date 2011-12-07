package org.springframework.security.oauth2.jackson;

import static org.junit.Assert.assertEquals;

import java.io.IOException;

import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.map.JsonMappingException;
import org.junit.Test;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * Tests serialization of an {@link OAuth2AccessToken} using jackson.
 *
 * @author Rob Winch
 */
@PrepareForTest(OAuth2AccessTokenJsonSerializer.class)
public class TestOAuth2AccessTokenJsonSerializer extends BaseOAuth2AccessTokenJacksonTest {

	@Test
	public void serializeNoRefresh() throws JsonGenerationException, JsonMappingException, IOException {
		accessToken.setRefreshToken(null);
		accessToken.setScope(null);
		String encodedAccessToken = mapper.writeValueAsString(accessToken);
		assertEquals(BaseOAuth2AccessTokenJacksonTest.ACCESS_TOKEN_NOREFRESH, encodedAccessToken);
	}

	@Test
	public void serializeWithRefresh() throws JsonGenerationException, JsonMappingException, IOException {
		accessToken.setScope(null);
		String encodedAccessToken = mapper.writeValueAsString(accessToken);
		assertEquals(BaseOAuth2AccessTokenJacksonTest.ACCESS_TOKEN_NOSCOPE, encodedAccessToken);
	}

	@Test
	public void serializeWithEmptyScope() throws JsonGenerationException, JsonMappingException, IOException {
		accessToken.getScope().clear();
		String encodedAccessToken = mapper.writeValueAsString(accessToken);
		assertEquals(BaseOAuth2AccessTokenJacksonTest.ACCESS_TOKEN_NOSCOPE, encodedAccessToken);
	}

	@Test
	public void serializeWithSingleScopes() throws JsonGenerationException, JsonMappingException, IOException {
		accessToken.getScope().remove(accessToken.getScope().iterator().next());
		String encodedAccessToken = mapper.writeValueAsString(accessToken);
		assertEquals(BaseOAuth2AccessTokenJacksonTest.ACCESS_TOKEN_SINGLESCOPE, encodedAccessToken);
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
		mapper.writeValueAsString(accessToken);
	}

	@Test
	public void serializeWithQuoteInScope() throws JsonGenerationException, JsonMappingException, IOException {
		accessToken.getScope().add("\"");
		String encodedAccessToken = mapper.writeValueAsString(accessToken);
		assertEquals("{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":10,\"scope\":\"\\\" read write\"}", encodedAccessToken);
	}

	@Test
	public void serializeWithMultiScopes() throws JsonGenerationException, JsonMappingException, IOException {
		String encodedAccessToken = mapper.writeValueAsString(accessToken);
		assertEquals(ACCESS_TOKEN_MULTISCOPE, encodedAccessToken);
	}
}