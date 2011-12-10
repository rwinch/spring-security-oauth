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
import java.util.Map;
import java.util.Map.Entry;

import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.JsonGenerator;
import org.codehaus.jackson.map.SerializerProvider;
import org.codehaus.jackson.map.ser.std.SerializerBase;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

public final class OAuth2ExceptionJsonSerializer extends SerializerBase<OAuth2Exception> {

	protected OAuth2ExceptionJsonSerializer() {
		super(OAuth2Exception.class);
	}

	@Override
	public void serialize(OAuth2Exception exception, JsonGenerator jgen, SerializerProvider provider) throws IOException,
			JsonGenerationException {
		jgen.writeStartObject();
		jgen.writeStringField(JsonOAuth2ErrorConstants.ERROR, exception.getOAuth2ErrorCode());
		jgen.writeStringField(JsonOAuth2ErrorConstants.DESCRIPTION, exception.getMessage());
		Map<String, String> moreInfo = exception.getAdditionalInformation();
		if(moreInfo != null) {
			for(Entry<String, String> entry : moreInfo.entrySet()) {
				jgen.writeStringField(entry.getKey(),entry.getValue());
			}
		}
		jgen.writeEndObject();
	}

}
