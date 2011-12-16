package org.springframework.security.oauth2.provider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.URI;
import java.util.StringTokenizer;

import org.codehaus.jackson.map.ObjectMapper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import com.gargoylesoftware.htmlunit.BrowserVersion;
import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebRequestSettings;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlSubmitInput;
import com.gargoylesoftware.htmlunit.html.HtmlTextInput;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class TestAuthorizationCodeProvider {

	private static ObjectMapper mapper;

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	@BeforeClass
	public static void setUpClass() {
		mapper = new ObjectMapper();
	}

	@AfterClass
	public static void tearDownClass() {
		mapper = null;
	}
	/**
	 * tests the basic authorization code provider
	 */
	@Test
	public void testBasicAuthorizationCodeProvider() throws Exception {

		WebClient userAgent = new WebClient(BrowserVersion.FIREFOX_3);
		userAgent.setRedirectEnabled(false);

		URI uri = serverRunning.buildUri("/sparklr2/oauth/authorize").queryParam("response_type", "code")
				.queryParam("state", "mystateid").queryParam("client_id", "my-less-trusted-client")
				.queryParam("redirect_uri", "http://anywhere").queryParam("scope", "read").build();
		String location = null;
		try {
			userAgent.getPage(uri.toString());
			fail("should have been redirected to the login form.");
		}
		catch (FailingHttpStatusCodeException e) {
			location = e.getResponse().getResponseHeaderValue("Location");
		}

		HtmlPage loginPage = userAgent.getPage(location);
		// should be directed to the login screen...
		HtmlForm loginForm = loginPage.getFormByName("loginForm");
		((HtmlTextInput) loginForm.getInputByName("j_username")).setValueAttribute("marissa");
		((HtmlTextInput) loginForm.getInputByName("j_password")).setValueAttribute("koala");
		try {
			((HtmlSubmitInput) loginForm.getInputByName("login")).click();
			fail("should have been redirected to the authorization endpoint.");
		}
		catch (FailingHttpStatusCodeException e) {
			location = e.getResponse().getResponseHeaderValue("Location");
		}

		HtmlPage confirmationPage = userAgent.getPage(location);
		HtmlForm okForm = confirmationPage.getFormByName("confirmationForm");
		try {
			((HtmlSubmitInput) okForm.getInputByName("authorize")).click();
			fail("should have been redirected to the redirect page.");
		}
		catch (FailingHttpStatusCodeException e) {
			location = e.getResponse().getResponseHeaderValue("Location");
		}

		URI redirection = serverRunning.buildUri(location).build();
		assertEquals("anywhere", redirection.getHost());
		assertEquals("http", redirection.getScheme());
		assertNotNull(redirection.getQuery());

		String code = null;
		String state = null;
		for (StringTokenizer queryTokens = new StringTokenizer(redirection.getQuery(), "&="); queryTokens
				.hasMoreTokens();) {
			String token = queryTokens.nextToken();
			if ("code".equals(token)) {
				if (code != null) {
					fail("shouldn't have returned more than one code.");
				}

				code = queryTokens.nextToken();
			}
			else if ("state".equals(token)) {
				state = queryTokens.nextToken();
			}
		}

		assertEquals("mystateid", state);
		assertNotNull(code);

		// we've got the authorization code. now we should be able to get an access token.
		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "authorization_code");
		formData.add("client_id", "my-less-trusted-client");
		formData.add("scope", "read");
		formData.add("redirect_uri", "http://anywhere");
		formData.add("code", code);
		formData.add("state", state);

		ResponseEntity<OAuth2AccessToken> response = serverRunning.postFor(OAuth2AccessToken.class,"/sparklr2/oauth/token", formData);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));
		OAuth2AccessToken accessToken = response.getBody();

		// let's try that request again and make sure we can't re-use the authorization code...
		try {
			serverRunning.postFor(OAuth2AccessToken.class,"/sparklr2/oauth/token", formData);
			fail("Expected Exception");
		}catch(ExtendedHttpClientErrorException success) {
			assertTrue(success.getOAuth2Exception() instanceof InvalidGrantException);
		}

		// now try and use the token to access a protected resource.

		// first make sure the resource is actually protected.
		assertNotSame(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/photos?format=json"));

		// now make sure an authorized request is valid.
		HttpHeaders headers = new HttpHeaders();
		headers.set("Authorization", String.format("%s %s", OAuth2AccessToken.BEARER_TYPE, accessToken.getValue()));
		assertEquals(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/photos?format=json", headers));
	}

	/**
	 * tests the basic authorization code provider
	 */
	@Test
	public void testBasicAuthorizationCodeProviderAsXml() throws Exception {

		WebClient userAgent = new WebClient(BrowserVersion.FIREFOX_3);
		userAgent.setRedirectEnabled(false);

		URI uri = serverRunning.buildUri("/sparklr2/oauth/authorize").queryParam("response_type", "code")
				.queryParam("state", "mystateid").queryParam("client_id", "my-less-trusted-client")
				.queryParam("redirect_uri", "http://anywhere").queryParam("scope", "read").build();
		String location = null;
		try {
			userAgent.getPage(uri.toString());
			fail("should have been redirected to the login form.");
		}
		catch (FailingHttpStatusCodeException e) {
			location = e.getResponse().getResponseHeaderValue("Location");
		}

		HtmlPage loginPage = userAgent.getPage(location);
		// should be directed to the login screen...
		HtmlForm loginForm = loginPage.getFormByName("loginForm");
		((HtmlTextInput) loginForm.getInputByName("j_username")).setValueAttribute("marissa");
		((HtmlTextInput) loginForm.getInputByName("j_password")).setValueAttribute("koala");
		try {
			((HtmlSubmitInput) loginForm.getInputByName("login")).click();
			fail("should have been redirected to the authorization endpoint.");
		}
		catch (FailingHttpStatusCodeException e) {
			location = e.getResponse().getResponseHeaderValue("Location");
		}

		HtmlPage confirmationPage = userAgent.getPage(location);
		HtmlForm okForm = confirmationPage.getFormByName("confirmationForm");
		try {
			((HtmlSubmitInput) okForm.getInputByName("authorize")).click();
			fail("should have been redirected to the redirect page.");
		}
		catch (FailingHttpStatusCodeException e) {
			location = e.getResponse().getResponseHeaderValue("Location");
		}

		URI redirection = serverRunning.buildUri(location).build();
		assertEquals("anywhere", redirection.getHost());
		assertEquals("http", redirection.getScheme());
		assertNotNull(redirection.getQuery());

		String code = null;
		String state = null;
		for (StringTokenizer queryTokens = new StringTokenizer(redirection.getQuery(), "&="); queryTokens
				.hasMoreTokens();) {
			String token = queryTokens.nextToken();
			if ("code".equals(token)) {
				if (code != null) {
					fail("shouldn't have returned more than one code.");
				}

				code = queryTokens.nextToken();
			}
			else if ("state".equals(token)) {
				state = queryTokens.nextToken();
			}
		}

		assertEquals("mystateid", state);
		assertNotNull(code);

		// we've got the authorization code. now we should be able to get an access token.
		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "authorization_code");
		formData.add("client_id", "my-less-trusted-client");
		formData.add("scope", "read");
		formData.add("redirect_uri", "http://anywhere");
		formData.add("code", code);
		formData.add("state", state);

		ResponseEntity<OAuth2AccessToken> response = serverRunning.postFor(OAuth2AccessToken.class,"/sparklr2/oauth/token?format=xml", formData);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));
		OAuth2AccessToken accessToken = response.getBody();

		// let's try that request again and make sure we can't re-use the authorization code...
		try {
			serverRunning.postFor(OAuth2AccessToken.class,"/sparklr2/oauth/token?format=xml", formData);
			fail("Expected Exception");
		}catch(ExtendedHttpClientErrorException success) {
			success.printStackTrace();
			assertTrue(success.getOAuth2Exception() instanceof InvalidGrantException);
		}

//		// now try and use the token to access a protected resource.
//
//		// first make sure the resource is actually protected.
//		assertNotSame(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/photos?format=json"));
//
//		// now make sure an authorized request is valid.
//		HttpHeaders headers = new HttpHeaders();
//		headers.set("Authorization", String.format("%s %s", OAuth2AccessToken.BEARER_TYPE, accessToken.getValue()));
//		assertEquals(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/photos?format=json", headers));
	}
	/**
	 * tests failure of getting the access token if some params are missing
	 */
	@Test
	public void testFailureIfSomeParametersAreMissing() throws Exception {

		WebClient userAgent = new WebClient(BrowserVersion.FIREFOX_3);
		userAgent.setRedirectEnabled(false);
		URI uri = serverRunning.buildUri("/sparklr2/oauth/authorize").queryParam("response_type", "code")
				.queryParam("state", "mystateid").queryParam("client_id", "my-less-trusted-client")
				.queryParam("redirect_uri", "http://anywhere").build();
		String location = null;
		try {
			userAgent.getPage(uri.toURL());
			fail("should have been redirected to the login form.");
		}
		catch (FailingHttpStatusCodeException e) {
			location = e.getResponse().getResponseHeaderValue("Location");
		}

		HtmlPage loginPage = userAgent.getPage(location);
		// should be directed to the login screen...
		HtmlForm loginForm = loginPage.getFormByName("loginForm");
		((HtmlTextInput) loginForm.getInputByName("j_username")).setValueAttribute("marissa");
		((HtmlTextInput) loginForm.getInputByName("j_password")).setValueAttribute("koala");
		try {
			((HtmlSubmitInput) loginForm.getInputByName("login")).click();
			fail("should have been redirected to the authorization endpoint.");
		}
		catch (FailingHttpStatusCodeException e) {
			location = e.getResponse().getResponseHeaderValue("Location");
		}

		HtmlPage confirmationPage = userAgent.getPage(location);
		HtmlForm okForm = confirmationPage.getFormByName("confirmationForm");
		try {
			((HtmlSubmitInput) okForm.getInputByName("authorize")).click();
		}
		catch (FailingHttpStatusCodeException e) {
			location = e.getResponse().getResponseHeaderValue("Location");
		}

		URI redirection = serverRunning.buildUri(location).build();
		assertEquals("anywhere", redirection.getHost());
		assertEquals("http", redirection.getScheme());
		assertNotNull(redirection.getQuery());

		String code = null;
		for (StringTokenizer queryTokens = new StringTokenizer(redirection.getQuery(), "&="); queryTokens
				.hasMoreTokens();) {
			String token = queryTokens.nextToken();
			if ("code".equals(token)) {
				if (code != null) {
					fail("shouldn't have returned more than one code.");
				}

				code = queryTokens.nextToken();
			}
		}

		assertNotNull(code);

		// we've got the authorization code. now let's make sure we get an error if we attempt to use a different
		// redirect uri
		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "authorization_code");
		formData.add("client_id", "my-less-trusted-client");
		formData.add("redirect_uri", "http://nowhere");
		formData.add("code", code);
		try {
			serverRunning.postFor(OAuth2AccessToken.class,"/sparklr2/oauth/token", formData);
			fail("Expected Exception");
		}catch(ExtendedHttpClientErrorException success) {
			ClientHttpResponse response = success.getResponse();
			assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
			assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));
			RedirectMismatchException oauthException = success.getOAuth2Exception();
		}
	}

	/**
	 * tests what happens if the user fails to authorize a token.
	 */
	@Test
	public void testUserFailsToAuthorize() throws Exception {

		WebClient userAgent = new WebClient(BrowserVersion.FIREFOX_3);
		userAgent.setRedirectEnabled(false);
		URI uri = serverRunning.buildUri("/sparklr2/oauth/authorize").queryParam("response_type", "code")
				.queryParam("state", "mystateid").queryParam("client_id", "my-less-trusted-client")
				.queryParam("redirect_uri", "http://anywhere").build();
		String location = null;
		try {
			userAgent.getPage(uri.toURL());
			fail("should have been redirected to the login form.");
		}
		catch (FailingHttpStatusCodeException e) {
			location = e.getResponse().getResponseHeaderValue("Location");
		}

		HtmlPage loginPage = userAgent.getPage(location);
		// should be directed to the login screen...
		HtmlForm loginForm = loginPage.getFormByName("loginForm");
		((HtmlTextInput) loginForm.getInputByName("j_username")).setValueAttribute("marissa");
		((HtmlTextInput) loginForm.getInputByName("j_password")).setValueAttribute("koala");
		try {
			((HtmlSubmitInput) loginForm.getInputByName("login")).click();
			fail("should have been redirected to the authorization endpoint.");
		}
		catch (FailingHttpStatusCodeException e) {
			location = e.getResponse().getResponseHeaderValue("Location");
		}

		HtmlPage confirmationPage = userAgent.getPage(location);
		HtmlForm nonoForm = confirmationPage.getFormByName("denialForm");
		try {
			((HtmlSubmitInput) nonoForm.getInputByName("deny")).click();
		}
		catch (FailingHttpStatusCodeException e) {
			location = e.getResponse().getResponseHeaderValue("Location");
		}

		// System.err.println(location);
		assertTrue(location.startsWith("http://anywhere"));
		assertTrue(location.substring(location.indexOf('?')).contains("error=access_denied"));
		assertTrue(location.contains("state=mystateid"));
	}

	/**
	 * tests what happens if the client id isn't provided.
	 */
	@Test
	public void testNoClientIdProvided() throws Exception {

		WebClient userAgent = new WebClient(BrowserVersion.FIREFOX_3);
		userAgent.setRedirectEnabled(false);
		URI uri = serverRunning.buildUri("/sparklr2/oauth/authorize").queryParam("response_type", "code")
				.queryParam("state", "mystateid")
				// .queryParam("client_id", "my-less-trusted-client")
				.queryParam("redirect_uri", "http://anywhere").build();
		try {
			userAgent.getPage(uri.toURL());
			fail("should have been a bad request.");
		}
		catch (FailingHttpStatusCodeException e) {
			// It's a bad request
			assertEquals(400, e.getResponse().getStatusCode());
		}

	}

	/**
	 * tests what happens if the client id is provided in header.
	 */
	@Test
	public void testClientIdProvidedInHeader() throws Exception {

		WebClient userAgent = new WebClient(BrowserVersion.FIREFOX_3);
		userAgent.setRedirectEnabled(false);
		URI uri = serverRunning.buildUri("/sparklr2/oauth/authorize").queryParam("response_type", "code")
				.queryParam("state", "mystateid")
				// .queryParam("client_id", "my-less-trusted-client")
				.queryParam("redirect_uri", "http://anywhere").build();
		WebRequestSettings settings = new WebRequestSettings(uri.toURL());
		settings.setAdditionalHeader("Authorization", String.format("Basic %s",
				new String(Base64.encode(String.format("%s:", "my-less-trusted-client").getBytes("UTF-8")), "UTF-8")));

		String location = null;
		try {
			userAgent.getPage(settings);
			fail("should have been redirected to the login form.");
		}
		catch (FailingHttpStatusCodeException e) {
			assertEquals(302, e.getResponse().getStatusCode());
			location  = e.getResponse().getResponseHeaderValue("Location");
		}

		assertTrue("Wrong location: "+location, location.contains("login.jsp"));

	}

	/**
	 * tests what happens if the client id isn't provided.
	 */
	@Test
	public void testNoClientIdProvidedAndNoRedirect() throws Exception {

		WebClient userAgent = new WebClient(BrowserVersion.FIREFOX_3);
		userAgent.setRedirectEnabled(false);
		URI uri = serverRunning.buildUri("/sparklr2/oauth/authorize").queryParam("response_type", "code")
				.queryParam("state", "mystateid").build();
		// .queryParam("client_id", "my-less-trusted-client")
		// .queryParam("redirect_uri", "http://anywhere");
		try {
			userAgent.getPage(uri.toURL());
			fail("should have been a bad request.");
		}
		catch (FailingHttpStatusCodeException e) {
			// It's a bad request
			assertEquals(400, e.getResponse().getStatusCode());
		}
	}

	@Test
	public void testRegisteredRedirectUri() throws Exception {

		WebClient userAgent = new WebClient(BrowserVersion.FIREFOX_3);
		userAgent.setRedirectEnabled(false);

		URI uri = serverRunning.buildUri("/sparklr2/oauth/authorize").queryParam("response_type", "code")
				.queryParam("state", "mystateid").queryParam("client_id", "my-client-with-registered-redirect")
				.queryParam("scope", "read").build();
		String location = null;
		try {
			userAgent.getPage(uri.toString());
			fail("should have been redirected to the login form.");
		}
		catch (FailingHttpStatusCodeException e) {
			location = e.getResponse().getResponseHeaderValue("Location");
		}

		HtmlPage loginPage = userAgent.getPage(location);
		// should be directed to the login screen...
		HtmlForm loginForm = loginPage.getFormByName("loginForm");
		((HtmlTextInput) loginForm.getInputByName("j_username")).setValueAttribute("marissa");
		((HtmlTextInput) loginForm.getInputByName("j_password")).setValueAttribute("koala");
		try {
			((HtmlSubmitInput) loginForm.getInputByName("login")).click();
			fail("should have been redirected to the authorization endpoint.");
		}
		catch (FailingHttpStatusCodeException e) {
			location = e.getResponse().getResponseHeaderValue("Location");
		}

		HtmlPage confirmationPage = userAgent.getPage(location);
		HtmlForm okForm = confirmationPage.getFormByName("confirmationForm");
		try {
			((HtmlSubmitInput) okForm.getInputByName("authorize")).click();
			fail("should have been redirected to the redirect page.");
		}
		catch (FailingHttpStatusCodeException e) {
			location = e.getResponse().getResponseHeaderValue("Location");
		}

		assertNotNull(location);
		URI redirection = serverRunning.buildUri(location).build();
		assertEquals("anywhere", redirection.getHost());
		assertEquals("http", redirection.getScheme());
		assertNotNull(redirection.getQuery());

		String code = null;
		String state = null;
		for (StringTokenizer queryTokens = new StringTokenizer(redirection.getQuery(), "&="); queryTokens
				.hasMoreTokens();) {
			String token = queryTokens.nextToken();
			if ("code".equals(token)) {
				if (code != null) {
					fail("shouldn't have returned more than one code.");
				}

				code = queryTokens.nextToken();
			}
			else if ("state".equals(token)) {
				state = queryTokens.nextToken();
			}
		}

		assertEquals("mystateid", state);
		assertNotNull(code);

		// we've got the authorization code. now we should be able to get an access token.
		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "client_credentials");
		formData.add("client_id", "my-client-with-registered-redirect");
		formData.add("scope", "trust");
		formData.add("state", state);

		ResponseEntity<OAuth2AccessToken> response = serverRunning.postFor(OAuth2AccessToken.class,"/sparklr2/oauth/token", formData);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));

		OAuth2AccessToken accessToken = response.getBody();

		// now try and use the token to access a protected resource.

		// first make sure the resource is actually protected.
		assertNotSame(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/trusted/message"));

		// now make sure an authorized request is valid.
		HttpHeaders headers = new HttpHeaders();
		headers.set("Authorization", String.format("%s %s", OAuth2AccessToken.BEARER_TYPE, accessToken.getValue()));
		assertEquals(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/trusted/message", headers));

	}

	@Test
	public void testInvalidScopeProvided() throws Exception {

		WebClient userAgent = new WebClient(BrowserVersion.FIREFOX_3);
		userAgent.setRedirectEnabled(false);

		URI uri = serverRunning.buildUri("/sparklr2/oauth/authorize").queryParam("response_type", "code")
				.queryParam("state", "mystateid").queryParam("client_id", "my-client-with-registered-redirect")
				.queryParam("scope", "nonexistent").build();
		String location = null;
		try {
			userAgent.getPage(uri.toString());
			fail("should have been redirected to the login form.");
		}
		catch (FailingHttpStatusCodeException e) {
			location = e.getResponse().getResponseHeaderValue("Location");
		}

		HtmlPage loginPage = userAgent.getPage(location);
		// should be directed to the login screen...
		HtmlForm loginForm = loginPage.getFormByName("loginForm");
		((HtmlTextInput) loginForm.getInputByName("j_username")).setValueAttribute("marissa");
		((HtmlTextInput) loginForm.getInputByName("j_password")).setValueAttribute("koala");
		try {
			((HtmlSubmitInput) loginForm.getInputByName("login")).click();
			fail("should have been redirected to the authorization endpoint.");
		}
		catch (FailingHttpStatusCodeException e) {
			location = e.getResponse().getResponseHeaderValue("Location");
		}

		HtmlPage confirmationPage = userAgent.getPage(location);
		HtmlForm okForm = confirmationPage.getFormByName("confirmationForm");
		try {
			((HtmlSubmitInput) okForm.getInputByName("authorize")).click();
			fail("should have been redirected to the redirect page.");
		}
		catch (FailingHttpStatusCodeException e) {
			location = e.getResponse().getResponseHeaderValue("Location");
		}

		URI redirection = serverRunning.buildUri(location).build();

		String code = null;
		String state = null;
		for (StringTokenizer queryTokens = new StringTokenizer(redirection.getQuery(), "&="); queryTokens
				.hasMoreTokens();) {
			String token = queryTokens.nextToken();
			if ("code".equals(token)) {
				if (code != null) {
					fail("shouldn't have returned more than one code.");
				}

				code = queryTokens.nextToken();
			}
			else if ("state".equals(token)) {
				state = queryTokens.nextToken();
			}
		}

		assertEquals("mystateid", state);
		assertNotNull(code);

		// we've got the authorization code. now we should be able to get an access token.
		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "authorization_code");
		formData.add("client_id", "my-client-with-registered-redirect");
		formData.add("code", code);

		try {
			serverRunning.postFor(OAuth2AccessToken.class,"/sparklr2/oauth/token", formData);
			fail("Expected Exception");
		}catch(ExtendedHttpClientErrorException success) {
			ClientHttpResponse response = success.getResponse();
			assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
			assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));
			InvalidScopeException oauthException = success.getOAuth2Exception();
		}
	}

	@Test
	public void testWrongRedirectUriProvided() throws Exception {

		WebClient userAgent = new WebClient(BrowserVersion.FIREFOX_3);
		userAgent.setRedirectEnabled(false);

		URI uri = serverRunning.buildUri("/sparklr2/oauth/authorize").queryParam("response_type", "code")
				.queryParam("state", "mystateid")
				.queryParam("client_id", "my-untrusted-client-with-registered-redirect").queryParam("scope", "read")
				.build();
		String location = null;
		try {
			userAgent.getPage(uri.toString());
			fail("should have been redirected to the login form.");
		}
		catch (FailingHttpStatusCodeException e) {
			location = e.getResponse().getResponseHeaderValue("Location");
		}

		HtmlPage loginPage = userAgent.getPage(location);
		// should be directed to the login screen...
		HtmlForm loginForm = loginPage.getFormByName("loginForm");
		((HtmlTextInput) loginForm.getInputByName("j_username")).setValueAttribute("marissa");
		((HtmlTextInput) loginForm.getInputByName("j_password")).setValueAttribute("koala");
		try {
			((HtmlSubmitInput) loginForm.getInputByName("login")).click();
			fail("should have been redirected to the authorization endpoint.");
		}
		catch (FailingHttpStatusCodeException e) {
			location = e.getResponse().getResponseHeaderValue("Location");
		}

		HtmlPage confirmationPage = userAgent.getPage(location);
		HtmlForm okForm = confirmationPage.getFormByName("confirmationForm");
		try {
			((HtmlSubmitInput) okForm.getInputByName("authorize")).click();
			fail("should have been redirected to the redirect page.");
		}
		catch (FailingHttpStatusCodeException e) {
			location = e.getResponse().getResponseHeaderValue("Location");
		}

		URI redirection = serverRunning.buildUri(location).build();
		assertEquals("anywhere", redirection.getHost());
		assertEquals("http", redirection.getScheme());
		assertNotNull(redirection.getQuery());

		String code = null;
		String state = null;
		for (StringTokenizer queryTokens = new StringTokenizer(redirection.getQuery(), "&="); queryTokens
				.hasMoreTokens();) {
			String token = queryTokens.nextToken();
			if ("code".equals(token)) {
				if (code != null) {
					fail("shouldn't have returned more than one code.");
				}

				code = queryTokens.nextToken();
			}
			else if ("state".equals(token)) {
				state = queryTokens.nextToken();
			}
		}

		assertEquals("mystateid", state);
		assertNotNull(code);

		// we've got the authorization code. now we should be able to get an access token.
		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "authorization_code");
		formData.add("client_id", "my-untrusted-client-with-registered-redirect");
		formData.add("scope", "read");
		formData.add("redirect_uri", "http://nowhere"); // should be ignored
		formData.add("code", code);
		formData.add("state", state);

		ResponseEntity<String> response = serverRunning.postForString("/sparklr2/oauth/token", formData);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));

	}

}
