/*
 * Copyright 2006-2010 the original author or authors.
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

/**
 * Constants used for OAuth2 JSON format defined in <a
 * href="http://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-5.1">Section 5.1</a>.
 * @author Rob Winch
 */
interface JsonOAuth2AccessTokenConstants {

	/**
	 * The access token issued by the authorization server. This value is REQUIRED.
	 */
	String ACCESS_TOKEN = "access_token";

	/**
	 * The type of the token issued as described in <a
	 * href="http://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-7.1">Section 7.1</a>. Value is case insensitive.
	 * This value is REQUIRED.
	 */
	String TOKEN_TYPE = "token_type";

	/**
	 * The lifetime in seconds of the access token. For example, the value "3600" denotes that the access token will
	 * expire in one hour from the time the response was generated. This value is OPTIONAL.
	 */
	String EXPIRES_IN = "expires_in";

	/**
	 * The refresh token which can be used to obtain new access tokens using the same authorization grant as described
	 * in <a href="http://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-6">Section 6</a>. This value is OPTIONAL.
	 */
	String REFRESH_TOKEN = "refresh_token";

	/**
	 * The scope of the access token as described by <a
	 * href="http://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-3.3">Section 3.3</a>
	 */
	String SCOPE = "scope";
}
