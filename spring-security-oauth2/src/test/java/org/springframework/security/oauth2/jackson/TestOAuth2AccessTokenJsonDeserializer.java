/*
 * Copyright 2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.oauth2.jackson;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.IOException;
import java.util.Date;
import java.util.HashSet;

import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.map.JsonMappingException;
import org.junit.Test;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.common.exceptions.UnauthorizedClientException;
import org.springframework.security.oauth2.common.exceptions.UnsupportedGrantTypeException;
import org.springframework.security.oauth2.common.exceptions.UserDeniedAuthorizationException;

/**
 * Tests deserialization of an {@link OAuth2AccessToken} using jackson.
 *
 * @author Rob Winch
 */
@PrepareForTest(OAuth2AccessTokenJsonDeserializer.class)
public class TestOAuth2AccessTokenJsonDeserializer extends BaseOAuth2AccessTokenJacksonTest {

	@Test
	public void serializeNoRefresh() throws JsonGenerationException, JsonMappingException, IOException {
		accessToken.setRefreshToken(null);
		accessToken.setScope(null);
		OAuth2AccessToken actual = mapper.readValue(ACCESS_TOKEN_NOREFRESH, OAuth2AccessToken.class);
		assertTokenEquals(accessToken,actual);
	}

	@Test
	public void serializeWithRefresh() throws JsonGenerationException, JsonMappingException, IOException {
		accessToken.setScope(null);
		OAuth2AccessToken actual = mapper.readValue(ACCESS_TOKEN_NOSCOPE, OAuth2AccessToken.class);
		assertTokenEquals(accessToken,actual);
	}

	@Test
	public void serializeWithSingleScopes() throws JsonGenerationException, JsonMappingException, IOException {
		accessToken.getScope().remove(accessToken.getScope().iterator().next());
		OAuth2AccessToken actual = mapper.readValue(ACCESS_TOKEN_SINGLESCOPE, OAuth2AccessToken.class);
		assertTokenEquals(accessToken,actual);
	}

	@Test
	public void deserializeWithEmptyStringScope() throws JsonGenerationException, JsonMappingException, IOException {
		accessToken.setScope(new HashSet<String>());
		OAuth2AccessToken actual = mapper.readValue(ACCESS_TOKEN_EMPTYSCOPE, OAuth2AccessToken.class);
		assertTokenEquals(accessToken,actual);
	}

	@Test
	public void deserializeWithMultiScopes() throws Exception {
		OAuth2AccessToken actual = mapper.readValue(ACCESS_TOKEN_MULTISCOPE, OAuth2AccessToken.class);
		assertTokenEquals(accessToken,actual);
	}

	@Test
	public void deserializeInvalidClient() throws Exception {
		thrown.expect(InvalidClientException.class);
		thrown.expectMessage("Details: some detail");
		String accessToken = createResponse(JsonOAuth2ErrorConstants.INVALID_CLIENT);
		mapper.readValue(accessToken, OAuth2AccessToken.class);
	}

	@Test
	public void deserializeInvalidGrant() throws Exception {
		thrown.expect(InvalidGrantException.class);
		thrown.expectMessage("Details: some detail");
		String accessToken = createResponse(JsonOAuth2ErrorConstants.INVALID_GRANT);
		mapper.readValue(accessToken, OAuth2AccessToken.class);
	}

	@Test
	public void deserializeInvalidRequest() throws Exception {
		thrown.expect(InvalidRequestException.class);
		thrown.expectMessage("Details: some detail");
		String accessToken = createResponse(JsonOAuth2ErrorConstants.INVALID_REQUEST);
		mapper.readValue(accessToken, OAuth2AccessToken.class);
	}

	@Test
	public void deserializeInvalidScope() throws Exception {
		thrown.expect(InvalidScopeException.class);
		thrown.expectMessage("Details: some detail");
		String accessToken = createResponse(JsonOAuth2ErrorConstants.INVALID_SCOPE);
		mapper.readValue(accessToken, OAuth2AccessToken.class);
	}

	@Test
	public void deserializeUnsupportedGrantType() throws Exception {
		thrown.expect(UnsupportedGrantTypeException.class);
		thrown.expectMessage("Details: some detail");
		String accessToken = createResponse(JsonOAuth2ErrorConstants.UNSUPPORTED_GRANT_TYPE);
		mapper.readValue(accessToken, OAuth2AccessToken.class);
	}

	@Test
	public void deserializeUnauthorizedClient() throws Exception {
		thrown.expect(UnauthorizedClientException.class);
		thrown.expectMessage("Details: some detail");
		String accessToken = createResponse(JsonOAuth2ErrorConstants.UNAUTHORIZED_CLIENT);
		mapper.readValue(accessToken, OAuth2AccessToken.class);
	}

	@Test
	public void deserializeAccessDenied() throws Exception {
		thrown.expect(UserDeniedAuthorizationException.class);
		thrown.expectMessage("Details: some detail");
		String accessToken = createResponse(JsonOAuth2ErrorConstants.ACCESS_DENIED);
		mapper.readValue(accessToken, OAuth2AccessToken.class);
	}

	@Test
	public void deserializeRedirectUriMismatch() throws Exception {
		thrown.expect(RedirectMismatchException.class);
		thrown.expectMessage("Details: some detail");
		String accessToken = createResponse(JsonOAuth2ErrorConstants.REDIRECT_URI_MISMATCH);
		mapper.readValue(accessToken, OAuth2AccessToken.class);
	}

	@Test
	public void deserializeInvalidToken() throws Exception {
		thrown.expect(InvalidTokenException.class);
		thrown.expectMessage("Details: some detail");
		String accessToken = createResponse(JsonOAuth2ErrorConstants.INVALID_TOKEN);
		mapper.readValue(accessToken, OAuth2AccessToken.class);
	}

	@Test
	public void deserializeUndefinedException() throws Exception {
		thrown.expect(OAuth2Exception.class);
		thrown.expectMessage("Details: some detail");
		String accessToken = createResponse("notdefinedcode");
		mapper.readValue(accessToken, OAuth2AccessToken.class);
	}

	private String createResponse(String error) {
		return "{\"error\":\""+error+"\",\"error_description\":\"some detail\"}";
	}

	private static void assertTokenEquals(OAuth2AccessToken expected, OAuth2AccessToken actual) {
		assertEquals(expected.getTokenType(), actual.getTokenType());
		assertEquals(expected.getValue(), actual.getValue());

		OAuth2RefreshToken expectedRefreshToken = expected.getRefreshToken();
		if (expectedRefreshToken == null) {
			assertNull(actual.getRefreshToken());
		}
		else {
			assertEquals(expectedRefreshToken.getValue(), actual.getRefreshToken().getValue());
		}
		assertEquals(expected.getScope(), actual.getScope());
		Date expectedExpiration = expected.getExpiration();
		if (expectedExpiration == null) {
			assertNull(actual.getExpiration());
		}
		else {
			assertEquals(expectedExpiration.getTime(), actual.getExpiration().getTime());
		}
	}
}