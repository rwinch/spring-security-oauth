package org.springframework.security.oauth2.provider;

import java.io.IOException;

import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.web.client.HttpClientErrorException;

public class ExtendedHttpClientErrorException extends HttpClientErrorException {
	private final ClientHttpResponse response;

	public ExtendedHttpClientErrorException(ClientHttpResponse response, Throwable ex) throws IOException {
		super(response.getStatusCode());
		initCause(ex);
		this.response = response;
	}

	public ClientHttpResponse getResponse() {
		return response;
	}

	public <T extends OAuth2Exception> T getOAuth2Exception() {
		return (T) getCause().getCause();
	}
}
