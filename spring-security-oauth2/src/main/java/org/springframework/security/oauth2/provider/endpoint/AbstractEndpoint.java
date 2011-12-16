/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.provider.endpoint;

import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.error.DefaultProviderExceptionHandler;
import org.springframework.security.oauth2.provider.error.ProviderExceptionHandler;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.ServletWebRequest;

/**
 * @author Dave Syer
 *
 */
public class AbstractEndpoint {

	protected final Log logger = LogFactory.getLog(getClass());

	private ProviderExceptionHandler providerExceptionHandler = new DefaultProviderExceptionHandler();

	private TokenGranter tokenGranter;

	private String credentialsCharset = "UTF-8";

	public void setCredentialsCharset(String credentialsCharset) {
		if (credentialsCharset == null) {
			throw new NullPointerException("credentials charset must not be null.");
		}

		this.credentialsCharset = credentialsCharset;
	}

	public void setProviderExceptionHandler(ProviderExceptionHandler providerExceptionHandler) {
		this.providerExceptionHandler = providerExceptionHandler;
	}

	public void setTokenGranter(TokenGranter tokenGranter) {
		this.tokenGranter = tokenGranter;
	}

	protected TokenGranter getTokenGranter() {
		return tokenGranter;
	}

	@ExceptionHandler(OAuth2Exception.class)
	public ResponseEntity<OAuth2Exception> handleException(OAuth2Exception e, ServletWebRequest webRequest) throws Exception {
		return providerExceptionHandler.handle(e);
	}

	/**
	 * Finds the client secret for the given client id and request. See the OAuth 2 spec, section 2.1.
	 *
	 * @param request The request.
	 * @return The client secret, or null if none found in the request.
	 */
	protected String[] findClientSecret(HttpHeaders headers, Map<String, String> parameters) {
		String clientSecret = parameters.get("client_secret");
		String clientId = parameters.get("client_id");
		if (clientSecret == null) {
			List<String> auths = headers.get("Authorization");
			if (auths != null) {

				for (String header : auths) {

					if (header.startsWith("Basic ")) {

						String token;
						try {
							byte[] base64Token = header.substring(6).trim().getBytes("UTF-8");
							token = new String(Base64.decode(base64Token), credentialsCharset);
						}
						catch (UnsupportedEncodingException e) {
							throw new IllegalStateException("Unsupported encoding", e);
						}

						String username = "";
						String password = "";
						int delim = token.indexOf(":");

						if (delim != -1) {
							username = token.substring(0, delim);
							password = token.substring(delim + 1);
						}

						if (clientId != null && !username.equals(clientId)) {
							continue;
						}
						clientId = username;
						clientSecret = password;
						break;

					}
				}
			}
		}
		return new String[] { clientId, clientSecret };
	}
}