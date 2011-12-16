package org.springframework.security.oauth2.provider;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.commons.httpclient.cookie.CookiePolicy;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Assume;
import org.junit.internal.AssumptionViolatedException;
import org.junit.rules.TestWatchman;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.Statement;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.CommonsClientHttpRequestFactory;
import org.springframework.security.oauth2.http.converter.OAuth2ResponseErrorHandler;
import org.springframework.security.oauth2.jaxb.JaxbOAuth2AccessTokenMessageConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.ResponseExtractor;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriTemplate;
import org.springframework.web.util.UriUtils;

/**
 * <p>
 * A rule that prevents integration tests from failing if the server application is not running or not accessible. If
 * the server is not running in the background all the tests here will simply be skipped because of a violated
 * assumption (showing as successful). Usage:
 * </p>
 *
 * <pre>
 * &#064;Rule public static BrokerRunning brokerIsRunning = BrokerRunning.isRunning();
 *
 * &#064;Test public void testSendAndReceive() throws Exception { // ... test using RabbitTemplate etc. }
 * </pre>
 * <p>
 * The rule can be declared as static so that it only has to check once for all tests in the enclosing test case, but
 * there isn't a lot of overhead in making it non-static.
 * </p>
 *
 * @see Assume
 * @see AssumptionViolatedException
 *
 * @author Dave Syer
 *
 */
@SuppressWarnings("deprecation")
public class ServerRunning extends TestWatchman {

	private static Log logger = LogFactory.getLog(ServerRunning.class);

	// Static so that we only test once on failure: speeds up test suite
	private static Map<Integer, Boolean> serverOnline = new HashMap<Integer, Boolean>();

	// Static so that we only test once on failure
	private static Map<Integer, Boolean> serverOffline = new HashMap<Integer, Boolean>();

	private final boolean assumeOnline;

	private static int DEFAULT_PORT = 8080;

	private static String DEFAULT_HOST = "localhost";

	private int port;

	private String hostName = DEFAULT_HOST;

	private RestTemplate client;

	/**
	 * @return a new rule that assumes an existing running broker
	 */
	public static ServerRunning isRunning() {
		return new ServerRunning(true);
	}

	/**
	 * @return a new rule that assumes there is no existing broker
	 */
	public static ServerRunning isNotRunning() {
		return new ServerRunning(false);
	}

	private ServerRunning(boolean assumeOnline) {
		this.assumeOnline = assumeOnline;
		setPort(DEFAULT_PORT);
	}

	/**
	 * @param port the port to set
	 */
	public void setPort(int port) {
		this.port = port;
		if (!serverOffline.containsKey(port)) {
			serverOffline.put(port, true);
		}
		if (!serverOnline.containsKey(port)) {
			serverOnline.put(port, true);
		}
		client = getRestTemplate();
	}

	/**
	 * @param hostName the hostName to set
	 */
	public void setHostName(String hostName) {
		this.hostName = hostName;
	}

	@Override
	public Statement apply(Statement base, FrameworkMethod method, Object target) {

		// Check at the beginning, so this can be used as a static field
		if (assumeOnline) {
			Assume.assumeTrue(serverOnline.get(port));
		}
		else {
			Assume.assumeTrue(serverOffline.get(port));
		}

		RestTemplate client = new RestTemplate();
		boolean followRedirects = HttpURLConnection.getFollowRedirects();
		HttpURLConnection.setFollowRedirects(false);
		boolean online = false;
		try {
			client.getForEntity(new UriTemplate(getUrl("/sparklr2/login.jsp")).toString(), String.class);
			online = true;
			logger.info("Basic connectivity test passed");
		}
		catch (RestClientException e) {
			logger.warn(String.format(
					"Not executing tests because basic connectivity test failed for hostName=%s, port=%d", hostName,
					port), e);
			if (assumeOnline) {
				Assume.assumeNoException(e);
			}
		}
		finally {
			HttpURLConnection.setFollowRedirects(followRedirects);
			if (online) {
				serverOffline.put(port, false);
				if (!assumeOnline) {
					Assume.assumeTrue(serverOffline.get(port));
				}

			}
			else {
				serverOnline.put(port, false);
			}
		}

		return super.apply(base, method, target);

	}

	public String getBaseUrl() {
		return "http://" + hostName + ":" + port;
	}

	public String getUrl(String path) {
		if (!path.startsWith("/")) {
			path = "/" + path;
		}
		return "http://" + hostName + ":" + port + path;
	}

	public ResponseEntity<String> postForString(String path, MultiValueMap<String, String> formData) {
		return postFor(String.class,path,formData);
	}

	public <T> ResponseEntity<T> postFor(Class<T> clazz, String path, MultiValueMap<String, String> formData) {
		HttpHeaders headers = new HttpHeaders();
		if(path.endsWith("format=xml")) {
			headers.setAccept(Arrays.asList(MediaType.APPLICATION_XML));
		} else {
			headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		}
		return client.exchange(getUrl(path), HttpMethod.POST, new HttpEntity<MultiValueMap<String, String>>(formData,
				headers), clazz);
	}

	public <T> ResponseEntity<T> postFor(Class<T> clazz, String path, HttpHeaders headers, MultiValueMap<String, String> formData) {
		HttpHeaders actualHeaders = new HttpHeaders();
		actualHeaders.putAll(headers);
		actualHeaders.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		return client.exchange(getUrl(path), HttpMethod.POST, new HttpEntity<MultiValueMap<String, String>>(formData,
				actualHeaders), clazz);
	}

	public ResponseEntity<String> postForString(String path, HttpHeaders headers, MultiValueMap<String, String> formData) {
		return postFor(String.class,path,headers,formData);
	}

	public ResponseEntity<Void> postForStatus(String path, HttpHeaders headers, MultiValueMap<String, String> formData) {
		HttpHeaders actualHeaders = new HttpHeaders();
		actualHeaders.putAll(headers);
		actualHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		return client.exchange(getUrl(path), HttpMethod.POST, new HttpEntity<MultiValueMap<String, String>>(formData,
				actualHeaders), null);
	}

	public ResponseEntity<String> getForString(String path) {
		return client.exchange(getUrl(path), HttpMethod.GET, new HttpEntity<Void>((Void) null), String.class);
	}

	public HttpStatus getStatusCode(String path, final HttpHeaders headers) {
		RequestCallback requestCallback = new NullRequestCallback();
		if (headers != null) {
			requestCallback = new RequestCallback() {
				public void doWithRequest(ClientHttpRequest request) throws IOException {
					request.getHeaders().putAll(headers);
				}
			};
		}
		return client.execute(getUrl(path), HttpMethod.GET, requestCallback,
				new ResponseExtractor<ResponseEntity<String>>() {
					public ResponseEntity<String> extractData(ClientHttpResponse response) throws IOException {
						return new ResponseEntity<String>(response.getStatusCode());
					}
				}).getStatusCode();
	}

	public HttpStatus getStatusCode(String path) {
		return getStatusCode(getUrl(path), null);
	}

	public RestTemplate getRestTemplate() {
		RestTemplate client = new RestTemplate();
		CommonsClientHttpRequestFactory requestFactory = new CommonsClientHttpRequestFactory() {
			@Override
			protected void postProcessCommonsHttpMethod(HttpMethodBase httpMethod) {
				httpMethod.setFollowRedirects(false);
				// We don't want stateful conversations for this test
				httpMethod.getParams().setCookiePolicy(CookiePolicy.IGNORE_COOKIES);
			}
		};
		client.setRequestFactory(requestFactory);
		client.setErrorHandler(new ResponseErrorHandler() {
			private OAuth2ResponseErrorHandler delegate = new OAuth2ResponseErrorHandler();
			// Pass errors through in response entity for status code analysis
			public boolean hasError(ClientHttpResponse response) throws IOException {
				return delegate.hasError(response);
			}

			public void handleError(ClientHttpResponse response) throws IOException {
				try {
					delegate.handleError(response);
				} catch(Exception e) {
					throw new ExtendedHttpClientErrorException(response, e);
				}
			}
		});
		client.getMessageConverters().add(0,new JaxbOAuth2AccessTokenMessageConverter());
		return client;
	}

	public UriBuilder buildUri(String url) {
		return UriBuilder.fromUri(url.startsWith("http:") ? url : getUrl(url));
	}

	private static final class NullRequestCallback implements RequestCallback {
		public void doWithRequest(ClientHttpRequest request) throws IOException {
		}
	}

	public static class UriBuilder {

		private final String url;

		private MultiValueMap<String, String> params = new LinkedMultiValueMap<String, String>();

		public UriBuilder(String url) {
			this.url = url;
		}

		public static UriBuilder fromUri(String url) {
			return new UriBuilder(url);
		}

		public UriBuilder queryParam(String key, String value) {
			params.add(key, value);
			return this;
		}

		public URI build() {
			StringBuilder builder = new StringBuilder();
			try {
				builder.append(url.replace(" ", "+"));
				if (!params.isEmpty()) {
					builder.append("?");
					boolean first = true;
					for (String key : params.keySet()) {
						if (!first) {
							builder.append("&");
						}
						else {
							first = false;
						}
						for (String value : params.get(key)) {
							builder.append(key + "=" + UriUtils.encodeQueryParam(value, "UTF-8"));
						}
					}
				}
				return new URI(builder.toString());
			}
			catch (UnsupportedEncodingException ex) {
				// should not happen, UTF-8 is always supported
				throw new IllegalStateException(ex);
			}
			catch (URISyntaxException ex) {
				throw new IllegalArgumentException("Could not create URI from [" + builder + "]: " + ex, ex);
			}
		}

	}

}
