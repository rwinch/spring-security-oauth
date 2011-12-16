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
package org.springframework.security.oauth2.http.converter.jackson;

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
import org.springframework.security.oauth2.http.converter.jackson.OAuth2AccessTokenJsonDeserializer;

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