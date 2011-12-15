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
package org.springframework.security.oauth2.provider.error;

import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.DefaultThrowableAnalyzer;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.web.util.ThrowableAnalyzer;

/**
 * @author Dave Syer
 *
 */
public class DefaultProviderExceptionHandler implements ProviderExceptionHandler {

	/** Logger available to subclasses */
	private static final Log logger = LogFactory.getLog(DefaultProviderExceptionHandler.class);

	private HttpMessageConverter<OAuth2Exception> converter;

	private ThrowableAnalyzer throwableAnalyzer = new DefaultThrowableAnalyzer();

	public ResponseEntity<OAuth2Exception> handle(Exception e) throws Exception {

		// Try to extract a SpringSecurityException from the stacktrace
		Throwable[] causeChain = throwableAnalyzer.determineCauseChain(e);
		RuntimeException ase = (AuthenticationException) throwableAnalyzer.getFirstThrowableOfType(
				AuthenticationException.class, causeChain);

		if (ase == null) {
			ase = (AccessDeniedException) throwableAnalyzer.getFirstThrowableOfType(AccessDeniedException.class,
					causeChain);
		}

		if (ase instanceof OAuth2Exception) {
			return handleSecurityException((OAuth2Exception) ase);
		}

		throw e;

	}

	private ResponseEntity<OAuth2Exception> handleSecurityException(OAuth2Exception e) throws IOException {

		if (logger.isDebugEnabled()) {
			logger.debug("OAuth error.", e);
		}

		int status = e.getHttpErrorCode();
		HttpHeaders headers = new HttpHeaders();
		headers.set("Cache-Control", "no-store");
		headers.setContentType(MediaType.APPLICATION_JSON);
		return new ResponseEntity<OAuth2Exception>(e,headers,HttpStatus.valueOf(status));
		// FIXME Remove Provider Exception Handler
//		converter.write(e, contentType, outputMessage)
//		String serialization = serializationService.serialize((OAuth2Exception) e);
//
//		ResponseEntity<String> response = new ResponseEntity<String>(serialization, headers, HttpStatus.valueOf(status));
//
//		return response;
//		return null;
	}

	public void setThrowableAnalyzer(ThrowableAnalyzer throwableAnalyzer) {
		this.throwableAnalyzer = throwableAnalyzer;
	}}
