package org.springframework.security.oauth2.provider;

import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.RestClientException;

public class ExtendedHttpClientErrorException extends RestClientException {
	private final ClientHttpResponse response;

	public ExtendedHttpClientErrorException(ClientHttpResponse response, Throwable ex) {
		super(ex.getMessage(), ex);
		this.response = response;
	}

	public ClientHttpResponse getResponse() {
		return response;
	}

}
