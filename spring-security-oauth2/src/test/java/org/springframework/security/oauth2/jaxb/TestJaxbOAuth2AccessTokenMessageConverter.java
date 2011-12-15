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
package org.springframework.security.oauth2.jaxb;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.Date;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;

@RunWith(PowerMockRunner.class)
@PrepareForTest({System.class,JaxbOAuth2AccessToken.class})
public class TestJaxbOAuth2AccessTokenMessageConverter {
	private static final String OAUTH_ACCESSTOKEN_NOEXPIRES = "<oauth><access_token>SlAV32hkKG</access_token></oauth>";
	private static final String OAUTH_ACCESSTOKEN_NOREFRESH = "<oauth><access_token>SlAV32hkKG</access_token><expires_in>10</expires_in></oauth>";
	private static final String OAUTH_ACCESSTOKEN = "<oauth><access_token>SlAV32hkKG</access_token><expires_in>10</expires_in><refresh_token>8xLOxBtZp8</refresh_token></oauth>";
	private JaxbOAuth2AccessTokenMessageConverter converter;
	private OAuth2AccessToken accessToken;
	private MediaType contentType;
	private ByteArrayOutputStream output;

	@Mock
	private Date expiration;
	@Mock
	private HttpOutputMessage outputMessage;
	@Mock
	private HttpInputMessage inputMessage;
	@Mock
	private HttpHeaders headers;

	@Before
	public void setUp() throws Exception {
		mockStatic(System.class);
		long now = 1323123715041L;
		when(System.currentTimeMillis()).thenReturn(now);
		when(expiration.before(any(Date.class))).thenReturn(false);
		when(expiration.getTime()).thenReturn(now + 10000);

		output = new ByteArrayOutputStream();
		converter = new JaxbOAuth2AccessTokenMessageConverter();
		contentType = MediaType.APPLICATION_XML;
		when(headers.getContentType()).thenReturn(contentType);
		when(outputMessage.getHeaders()).thenReturn(headers);
		when(outputMessage.getBody()).thenReturn(output);

		accessToken = new OAuth2AccessToken("SlAV32hkKG");
		accessToken.setExpiration(expiration);
		accessToken.setRefreshToken(new OAuth2RefreshToken("8xLOxBtZp8"));
	}

	@Test
	public void writeAccessToken() throws IOException {
		converter.write(accessToken, contentType, outputMessage);
		assertEquals(OAUTH_ACCESSTOKEN,getOutput());
	}

	@Test
	public void writeAccessTokenNoRefresh() throws IOException {
		accessToken.setRefreshToken(null);
		converter.write(accessToken, contentType, outputMessage);
		assertEquals(OAUTH_ACCESSTOKEN_NOREFRESH,getOutput());
	}

	@Test
	public void writeAccessTokenNoExpires() throws IOException {
		accessToken.setRefreshToken(null);
		accessToken.setExpiration(null);
		converter.write(accessToken, contentType, outputMessage);
		assertEquals(OAUTH_ACCESSTOKEN_NOEXPIRES,getOutput());
	}

	@Test
	public void readAccessToken() throws IOException {
		when(inputMessage.getBody()).thenReturn(createInputStream(OAUTH_ACCESSTOKEN));
		OAuth2AccessToken token = converter.read(OAuth2AccessToken.class, inputMessage);
		assertTokenEquals(accessToken,token);
	}

	@Test
	public void readAccessTokenNoRefresh() throws IOException {
		accessToken.setRefreshToken(null);
		when(inputMessage.getBody()).thenReturn(createInputStream(OAUTH_ACCESSTOKEN_NOREFRESH));
		OAuth2AccessToken token = converter.read(OAuth2AccessToken.class, inputMessage);
		assertTokenEquals(accessToken,token);
	}

	@Test
	public void readAccessTokenNoExpires() throws IOException {
		accessToken.setRefreshToken(null);
		accessToken.setExpiration(null);
		when(inputMessage.getBody()).thenReturn(createInputStream(OAUTH_ACCESSTOKEN_NOEXPIRES));
		OAuth2AccessToken token = converter.read(OAuth2AccessToken.class, inputMessage);
		assertTokenEquals(accessToken,token);
	}

	private InputStream createInputStream(String in) throws UnsupportedEncodingException {
		return new ByteArrayInputStream(in.getBytes("UTF-8"));
	}

	private String getOutput() throws UnsupportedEncodingException {
		return output.toString("UTF-8");
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
