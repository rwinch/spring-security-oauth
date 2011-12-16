package org.springframework.security.oauth2.client.token;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.Arrays;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.DefaultOAuth2AccessTokenResponseExtractor;
import org.springframework.security.oauth2.client.DefaultOAuth2ExceptionTokenResponseExtractor;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.auth.ClientAuthenticationHandler;
import org.springframework.security.oauth2.client.token.auth.DefaultClientAuthenticationHandler;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.ResponseExtractor;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

/**
 * Base support logic for obtaining access tokens.
 *
 * @author Ryan Heaton
 * @author Dave Syer
 */
public abstract class OAuth2AccessTokenSupport implements InitializingBean {

	protected final Log logger = LogFactory.getLog(getClass());

	private static final FormHttpMessageConverter FORM_MESSAGE_CONVERTER = new FormHttpMessageConverter();

	private final RestTemplate restTemplate;

	private ClientAuthenticationHandler authenticationHandler = new DefaultClientAuthenticationHandler();

	protected OAuth2AccessTokenSupport() {
		this.restTemplate = new RestTemplate();
		this.restTemplate.setErrorHandler(new AccessTokenErrorHandler());
		this.restTemplate.setRequestFactory(new SimpleClientHttpRequestFactory() {
			@Override
			protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
				super.prepareConnection(connection, httpMethod);
				connection.setInstanceFollowRedirects(false);
			}
		});
	}

	public void afterPropertiesSet() throws Exception {
		Assert.notNull(restTemplate, "A RestTemplate is required.");
	}

	protected RestTemplate getRestTemplate() {
		return restTemplate;
	}

	protected ClientAuthenticationHandler getAuthenticationHandler() {
		return authenticationHandler;
	}

	public void setAuthenticationHandler(ClientAuthenticationHandler authenticationHandler) {
		this.authenticationHandler = authenticationHandler;
	}

	protected OAuth2AccessToken retrieveToken(MultiValueMap<String, String> form,
			OAuth2ProtectedResourceDetails resource) {

		try {
			// Prepare headers and form before going into rest template call in case the URI is affected by the result
			HttpHeaders headers = new HttpHeaders();
			getAuthenticationHandler().authenticateTokenRequest(resource, form, headers);

			return getRestTemplate().execute(getAccessTokenUri(resource, form), getHttpMethod(),
					getRequestCallback(resource, form, headers), getResponseExtractor(), form.toSingleValueMap());

		}
		catch (OAuth2Exception oe) {
			throw new OAuth2AccessDeniedException("Access token denied.", resource, oe);
		}
		catch (RestClientException rce) {
			throw new OAuth2AccessDeniedException("Error requesting access token.", resource, rce);
		}

	}

	protected HttpMethod getHttpMethod() {
		return HttpMethod.POST;
	}

	protected String getAccessTokenUri(OAuth2ProtectedResourceDetails resource, MultiValueMap<String, String> form) {

		String accessTokenUri = resource.getAccessTokenUri();

		if (logger.isDebugEnabled()) {
			logger.debug("Retrieving token from " + accessTokenUri);
		}

		StringBuilder builder = new StringBuilder(accessTokenUri);

		if (getHttpMethod() == HttpMethod.GET) {
			String separator = "?";
			if (accessTokenUri.contains("?")) {
				separator = "&";
			}

			for (String key : form.keySet()) {
				builder.append(separator);
				builder.append(key + "={" + key + "}");
				separator = "&";
			}
		}

		return builder.toString();

	}

	protected ResponseExtractor<OAuth2AccessToken> getResponseExtractor() {
		return new DefaultOAuth2AccessTokenResponseExtractor();
	}

	protected RequestCallback getRequestCallback(OAuth2ProtectedResourceDetails resource,
			MultiValueMap<String, String> form, HttpHeaders headers) {
		return new OAuth2AuthTokenCallback(form, headers);
	}

	/**
	 * Request callback implementation that writes the given object to the request stream.
	 */
	private class OAuth2AuthTokenCallback implements RequestCallback {

		private final MultiValueMap<String, String> form;

		private final HttpHeaders headers;

		private OAuth2AuthTokenCallback(MultiValueMap<String, String> form, HttpHeaders headers) {
			this.form = form;
			this.headers = headers;
		}

		public void doWithRequest(ClientHttpRequest request) throws IOException {
			request.getHeaders().putAll(this.headers);
			request.getHeaders().setAccept(
					Arrays.asList(MediaType.APPLICATION_JSON, MediaType.APPLICATION_FORM_URLENCODED));
			FORM_MESSAGE_CONVERTER.write(this.form, MediaType.APPLICATION_FORM_URLENCODED, request);
		}
	}

	private class AccessTokenErrorHandler extends DefaultResponseErrorHandler {
		private ResponseExtractor<OAuth2Exception> exceptionExtractor = new DefaultOAuth2ExceptionTokenResponseExtractor();
		@Override
		public void handleError(ClientHttpResponse response) throws IOException {
			MediaType contentType = response.getHeaders().getContentType();
			if (contentType != null
					&& (response.getStatusCode().value() == 400 || response.getStatusCode().value() == 401)) {
				throw exceptionExtractor.extractData(response);
			}

			super.handleError(response);
		}

	}
}
