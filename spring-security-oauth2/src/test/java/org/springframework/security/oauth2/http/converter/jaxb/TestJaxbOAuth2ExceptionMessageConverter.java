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
package org.springframework.security.oauth2.http.converter.jaxb;

import static org.junit.Assert.*;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.when;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;
import org.junit.internal.runners.statements.Fail;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.http.converter.jaxb.JaxbOAuth2AccessToken;
import org.springframework.security.oauth2.http.converter.jaxb.JaxbOAuth2ExceptionMessageConverter;

@RunWith(PowerMockRunner.class)
@PrepareForTest({System.class,JaxbOAuth2AccessToken.class})
public class TestJaxbOAuth2ExceptionMessageConverter extends BaseJaxbMessageConverterTest {
	private JaxbOAuth2ExceptionMessageConverter converter;
	private OAuth2Exception exception;
	private static String DETAILS = "some detail";

	@Before
	public void before() throws Exception {
		converter = new JaxbOAuth2ExceptionMessageConverter();
	}

	@Test
	public void writeInvalidClient() throws IOException {
		exception = new InvalidClientException(DETAILS);
		String expected = createResponse(exception.getOAuth2ErrorCode());
		converter.write(exception, contentType, outputMessage);
		assertEquals(expected,getOutput());
	}

	@Test
	public void readInvalidClient() throws IOException {
		exception = new InvalidClientException(DETAILS);
		String toRead = createResponse(exception.getOAuth2ErrorCode());
		when(inputMessage.getBody()).thenReturn(createInputStream(toRead));
		InvalidClientException result = (InvalidClientException) converter.read(InvalidClientException.class, inputMessage);
	}

	private String createResponse(String error) {
		return "<oauth><error_description>some detail</error_description><error>"+error+"</error></oauth>";
	}
}
