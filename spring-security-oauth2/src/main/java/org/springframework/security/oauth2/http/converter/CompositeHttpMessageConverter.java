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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.converter.json.MappingJacksonHttpMessageConverter;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.jaxb.JaxbOAuth2AccessTokenMessageConverter;
import org.springframework.security.oauth2.jaxb.JaxbOAuth2ExceptionMessageConverter;

public final class CompositeHttpMessageConverter<T> implements HttpMessageConverter<T> {
	public static final CompositeHttpMessageConverter<OAuth2AccessToken> ACCESS_TOKEN_CONVERTER = new CompositeHttpMessageConverter(
			new JaxbOAuth2AccessTokenMessageConverter(),new MappingJacksonHttpMessageConverter(), new FormOAuth2AccessTokenMessageConverter());

	public static final CompositeHttpMessageConverter<OAuth2Exception> OAUTH2_EXCEPTION_CONVERTER = new CompositeHttpMessageConverter(
			new JaxbOAuth2ExceptionMessageConverter(),new MappingJacksonHttpMessageConverter(), new FormOAuth2ExceptionHttpMessageConverter());

	private List<HttpMessageConverter<Object>> delegates;
	private List<MediaType> mediaTypes;

	public CompositeHttpMessageConverter(HttpMessageConverter<Object>... delegates) {
		this.delegates = Arrays.asList(delegates);
		Set<MediaType> mediaTypes = new HashSet<MediaType>();
		for(HttpMessageConverter<Object> delegate : delegates) {
			mediaTypes.addAll(delegate.getSupportedMediaTypes());
		}
		this.mediaTypes = Collections.unmodifiableList(new ArrayList<MediaType>(mediaTypes));
	}

	public boolean canRead(Class<?> clazz, MediaType mediaType) {
		for(HttpMessageConverter<Object> delegate : delegates) {
			if(delegate.canRead(clazz, mediaType)) {
				return true;
			}
		}
		return false;
	}

	public boolean canWrite(Class<?> clazz, MediaType mediaType) {
		for(HttpMessageConverter<Object> delegate : delegates) {
			if(delegate.canWrite(clazz, mediaType)) {
				return true;
			}
		}
		return false;
	}

	public List<MediaType> getSupportedMediaTypes() {
		return mediaTypes;
	}

	public T read(Class<? extends T> clazz, HttpInputMessage inputMessage) throws IOException,
			HttpMessageNotReadableException {
		for(HttpMessageConverter<Object> delegate : delegates) {
			if(delegate.canRead(clazz, inputMessage.getHeaders().getContentType())) {
				return (T) delegate.read(clazz, inputMessage);
			}
		}
		throw new HttpMessageNotReadableException("Cannot read for input "+clazz);
	}

	public void write(T t, MediaType contentType, HttpOutputMessage outputMessage) throws IOException,
			HttpMessageNotWritableException {
		for(HttpMessageConverter<Object> delegate : delegates) {
			if(delegate.canWrite(t.getClass(), contentType)) {
				delegate.write(t, contentType, outputMessage);
				return;
			}
		}
		throw new HttpMessageNotWritableException("Cannot write "+t+" for contentType "+contentType);
	}

}
