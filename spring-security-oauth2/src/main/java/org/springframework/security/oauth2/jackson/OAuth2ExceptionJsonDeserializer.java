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

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.codehaus.jackson.JsonParser;
import org.codehaus.jackson.JsonProcessingException;
import org.codehaus.jackson.JsonToken;
import org.codehaus.jackson.map.DeserializationContext;
import org.codehaus.jackson.map.deser.StdDeserializer;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.common.exceptions.UnauthorizedClientException;
import org.springframework.security.oauth2.common.exceptions.UnsupportedGrantTypeException;
import org.springframework.security.oauth2.common.exceptions.UnsupportedResponseTypeException;
import org.springframework.security.oauth2.common.exceptions.UserDeniedAuthorizationException;

@SuppressWarnings("deprecation")
public final class OAuth2ExceptionJsonDeserializer  extends StdDeserializer<OAuth2Exception> {

	protected OAuth2ExceptionJsonDeserializer() {
		super(OAuth2Exception.class);
	}

	@Override
	public OAuth2Exception deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException,
			JsonProcessingException {

		String errorType = null;
		String errorDesc = "N/A";
		Map<String,String> moreInfo = new HashMap<String,String>();
		while (jp.nextToken() != JsonToken.END_OBJECT) {
			String name = jp.getCurrentName();
			jp.nextToken();
			String value = jp.getText();
			if(JsonOAuth2ErrorConstants.ERROR.equals(name)) {
				errorType = value;
			} else if (JsonOAuth2ErrorConstants.DESCRIPTION.equals(name)) {
				errorDesc = value;
			} else {
				moreInfo.put(name,value);
			}
		}
		OAuth2Exception result = null;
		String errorMessage = "Invalid access token. Details: "+errorDesc;
		if(JsonOAuth2ErrorConstants.INVALID_REQUEST.equals(errorType)) {
			result = new InvalidRequestException(errorMessage);
		} else if(JsonOAuth2ErrorConstants.INVALID_CLIENT.equals(errorType)) {
			result = new InvalidClientException(errorMessage);
		} else if(JsonOAuth2ErrorConstants.INVALID_GRANT.equals(errorType)) {
			result = new InvalidGrantException(errorMessage);
		} else if(JsonOAuth2ErrorConstants.UNAUTHORIZED_CLIENT.equals(errorType)) {
			result = new UnauthorizedClientException(errorMessage);
		} else if(JsonOAuth2ErrorConstants.UNSUPPORTED_GRANT_TYPE.equals(errorType)) {
			result = new UnsupportedGrantTypeException(errorMessage);
		} else if(JsonOAuth2ErrorConstants.INVALID_SCOPE.equals(errorType)) {
			result = new InvalidScopeException(errorMessage);
		} else if (JsonOAuth2ErrorConstants.INVALID_TOKEN.equals(errorType)) {
			result = new InvalidTokenException(errorMessage);
		} else if (JsonOAuth2ErrorConstants.REDIRECT_URI_MISMATCH.equals(errorType)) {
			result = new RedirectMismatchException(errorMessage);
		} else if (JsonOAuth2ErrorConstants.UNSUPPORTED_RESPONSE_TYPE.equals(errorType)) {
			result = new UnsupportedResponseTypeException(errorMessage);
		} else if (JsonOAuth2ErrorConstants.ACCESS_DENIED.equals(errorType)) {
			result = new UserDeniedAuthorizationException(errorMessage);
		} else {
			result = new OAuth2Exception(errorMessage);
		}
		for(Map.Entry<String,String> info : moreInfo.entrySet()) {
			result.addAdditionalInformation(info.getKey(), info.getValue());
		}
		return result;
	}
}
