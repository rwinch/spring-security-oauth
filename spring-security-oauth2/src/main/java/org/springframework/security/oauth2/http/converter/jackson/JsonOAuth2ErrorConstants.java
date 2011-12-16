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

public interface JsonOAuth2ErrorConstants {
	String ERROR = "error";
	String DESCRIPTION = "error_description";
	String URI = "error_uri";
	String INVALID_REQUEST = "invalid_request";
	String INVALID_CLIENT = "invalid_client";
	String INVALID_GRANT = "invalid_grant";
	String UNAUTHORIZED_CLIENT = "unauthorized_client";
	String UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";
	String INVALID_SCOPE = "invalid_scope";
	String INVALID_TOKEN = "invalid_token";
	String REDIRECT_URI_MISMATCH ="redirect_uri_mismatch";
	String UNSUPPORTED_RESPONSE_TYPE ="unsupported_response_type";
	String ACCESS_DENIED = "access_denied";
}
