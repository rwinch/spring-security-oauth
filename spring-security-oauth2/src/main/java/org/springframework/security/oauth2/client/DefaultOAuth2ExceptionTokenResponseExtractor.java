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
package org.springframework.security.oauth2.client;

import java.util.Arrays;

import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJacksonHttpMessageConverter;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.http.converter.FormOAuth2ExceptionHttpMessageConverter;
import org.springframework.security.oauth2.http.converter.jaxb.JaxbOAuth2ExceptionMessageConverter;
import org.springframework.web.client.HttpMessageConverterExtractor;

public class DefaultOAuth2ExceptionTokenResponseExtractor extends HttpMessageConverterExtractor<OAuth2Exception> {

	public DefaultOAuth2ExceptionTokenResponseExtractor() {
		super(OAuth2Exception.class, Arrays.<HttpMessageConverter<?>> asList(
				new JaxbOAuth2ExceptionMessageConverter(), new MappingJacksonHttpMessageConverter(),
				new FormOAuth2ExceptionHttpMessageConverter()));
	}
}
