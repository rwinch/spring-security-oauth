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
package org.springframework.security.oauth2.http.converter;

import java.io.IOException;
import java.nio.charset.Charset;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResponseErrorHandler;

public class OAuth2ResponseErrorHandler implements ResponseErrorHandler {
	private HttpMessageConverter<Object> messageConverter;

	public boolean hasError(ClientHttpResponse response) throws IOException {
		HttpStatus statusCode = response.getStatusCode();
		return HttpStatus.BAD_REQUEST.equals(statusCode) || HttpStatus.UNAUTHORIZED.equals(statusCode);
	}

	public void handleError(ClientHttpResponse response) throws IOException {
		OAuth2Exception result = (OAuth2Exception) messageConverter.read(OAuth2Exception.class, response);
		HttpStatus statusCode = response.getStatusCode();
		MediaType contentType = response.getHeaders().getContentType();
		Charset charset = contentType != null ? contentType.getCharSet() : null;
		byte[] body = FileCopyUtils.copyToByteArray(response.getBody());
		HttpClientErrorException httpClientErrorException = new HttpClientErrorException(statusCode, response.getStatusText(), body, charset);
		throw (HttpClientErrorException) httpClientErrorException.initCause(result);
	}
}
