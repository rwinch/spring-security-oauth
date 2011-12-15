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
package org.springframework.security.oauth2.provider.filter;

import java.io.IOException;
import java.util.List;
import java.util.Map.Entry;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.http.converter.CompositeHttpMessageConverter;
import org.springframework.security.oauth2.provider.error.DefaultProviderExceptionHandler;
import org.springframework.security.oauth2.provider.error.ProviderExceptionHandler;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Filter for handling OAuth2-specific exceptions.
 *
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class OAuth2ExceptionHandlerFilter extends GenericFilterBean {

	private ProviderExceptionHandler providerExceptionHandler = new DefaultProviderExceptionHandler();

	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException,
			ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		try {
			chain.doFilter(request, response);

			if (logger.isDebugEnabled()) {
				logger.debug("Chain processed normally");
			}
		}
		catch (IOException ex) {
			throw ex;
		}
		catch (Exception ex) {

			try {
				ResponseEntity<OAuth2Exception> result = providerExceptionHandler.handle(ex);
				HttpMessageConverter<OAuth2Exception> converter = CompositeHttpMessageConverter.OAUTH2_EXCEPTION_CONVERTER;
				response.setStatus(result.getStatusCode().value());
				for (Entry<String, List<String>> entry : result.getHeaders().entrySet()) {
					for (String value : entry.getValue()) {
						response.addHeader(entry.getKey(), value);
					}
				}
				converter.write(result.getBody(), result.getHeaders().getContentType(), new ServletServerHttpResponse(response));
			}
			catch (ServletException e) {
				throw e;
			}
			catch (IOException e) {
				throw e;
			}
			catch (RuntimeException e) {
				throw e;
			}
			catch (Exception e) {
				// Wrap other Exceptions. These are not expected to happen
				throw new RuntimeException(e);

			}
		}
	}

	public void setProviderExceptionHandler(ProviderExceptionHandler providerExceptionHandler) {
		this.providerExceptionHandler = providerExceptionHandler;
	}

}
