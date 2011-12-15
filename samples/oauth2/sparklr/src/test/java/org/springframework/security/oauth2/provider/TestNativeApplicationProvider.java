package org.springframework.security.oauth2.provider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.List;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.DefaultOAuth2SerializationService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class TestNativeApplicationProvider {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	/**
	 * tests a happy-day flow of the native application provider.
	 */
	@Test
	public void testHappyDayWithForm() throws Exception {

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "password");
		formData.add("client_id", "my-trusted-client");
		formData.add("scope", "read");
		formData.add("username", "marissa");
		formData.add("password", "koala");

		ResponseEntity<String> response = serverRunning.postForString("/sparklr2/oauth/token", formData);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));

		DefaultOAuth2SerializationService serializationService = new DefaultOAuth2SerializationService();
		OAuth2AccessToken accessToken = serializationService.deserializeJsonAccessToken(new ByteArrayInputStream(
				response.getBody().getBytes()));

		// now try and use the token to access a protected resource.

		// first make sure the resource is actually protected.
		assertNotSame(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/photos?format=json"));

		// now make sure an authorized request is valid.
		HttpHeaders headers = new HttpHeaders();
		headers.set("Authorization", String.format("%s %s", OAuth2AccessToken.BEARER_TYPE, accessToken.getValue()));
		assertEquals(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/photos?format=json", headers));
	}

	/**
	 * tests a happy-day flow of the native application provider.
	 */
	@Test
	public void testHappyDayWithHeader() throws Exception {

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "password");
		formData.add("scope", "read");
		formData.add("username", "marissa");
		formData.add("password", "koala");

		HttpHeaders headers = new HttpHeaders();
		headers.set("Authorization",
				String.format("Basic %s", new String(Base64.encode("my-trusted-client:".getBytes("UTF-8")), "UTF-8")));
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

		ResponseEntity<String> response = serverRunning.postForString("/sparklr2/oauth/token", headers, formData);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));

		DefaultOAuth2SerializationService serializationService = new DefaultOAuth2SerializationService();
		OAuth2AccessToken accessToken = serializationService.deserializeJsonAccessToken(new ByteArrayInputStream(
				response.getBody().getBytes()));

		// now try and use the token to access a protected resource.

		// first make sure the resource is actually protected.
		assertNotSame(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/photos?format=json"));

		// now make sure an authorized request is valid.
		headers = new HttpHeaders();
		headers.set("Authorization", String.format("%s %s", OAuth2AccessToken.BEARER_TYPE, accessToken.getValue()));
		assertEquals(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/photos?format=json", headers));
	}

	/**
	 * tests a happy-day flow of the native application profile.
	 */
	@Test
	public void testSecretRequired() throws Exception {
		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "password");
		formData.add("client_id", "my-trusted-client-with-secret");
		formData.add("username", "marissa");
		formData.add("password", "koala");
		ResponseEntity<String> response = serverRunning.postForString("/sparklr2/oauth/token", formData);
		assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
	}

	/**
	 * tests a happy-day flow of the native application provider.
	 */
	@Test
	public void testSecretProvided() throws Exception {
		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "password");
		formData.add("client_id", "my-trusted-client-with-secret");
		formData.add("client_secret", "somesecret");
		formData.add("username", "marissa");
		formData.add("password", "koala");
		ResponseEntity<String> response = serverRunning.postForString("/sparklr2/oauth/token", formData);
		assertEquals(HttpStatus.OK, response.getStatusCode());
	}

	/**
	 * tests a happy-day flow of the native application provider.
	 */
	@Test
	public void testSecretProvidedInHeader() throws Exception {
		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "password");
		formData.add("username", "marissa");
		formData.add("password", "koala");
		HttpHeaders headers = new HttpHeaders();
		headers.set("Authorization",
				"Basic " + new String(Base64.encode("my-trusted-client-with-secret:somesecret".getBytes())));
		ResponseEntity<String> response = serverRunning.postForString("/sparklr2/oauth/token", headers, formData);
		assertEquals(HttpStatus.OK, response.getStatusCode());
	}

	/**
	 * tests that an error occurs if you attempt to use username/password creds for a non-password grant type.
	 */
	@Test
	public void testInvalidGrantType() throws Exception {

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "password");
		formData.add("client_id", "my-untrusted-client-with-registered-redirect");
		formData.add("username", "marissa");
		formData.add("password", "koala");
		ResponseEntity<String> response = serverRunning.postForString("/sparklr2/oauth/token", formData);
		assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
		List<String> newCookies = response.getHeaders().get("Set-Cookie");
		if (newCookies != null && !newCookies.isEmpty()) {
			fail("No cookies should be set. Found: " + newCookies.get(0) + ".");
		}
		assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));

		DefaultOAuth2SerializationService serializationService = new DefaultOAuth2SerializationService();
		try {
			throw serializationService.deserializeJsonError(new ByteArrayInputStream(response.getBody().getBytes()));
		} catch (OAuth2Exception e) {
			assertEquals("invalid_grant", e.getOAuth2ErrorCode());
		}
	}

	/**
	 * tests a happy-day flow of the native application provider.
	 */
	@Test
	public void testClientRoleBasedSecurity() throws Exception {

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "password");
		formData.add("client_id", "my-trusted-client");
		formData.add("scope", "trust");
		formData.add("username", "marissa");
		formData.add("password", "koala");

		ResponseEntity<String> response = serverRunning.postForString("/sparklr2/oauth/token", formData);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));

		DefaultOAuth2SerializationService serializationService = new DefaultOAuth2SerializationService();
		OAuth2AccessToken accessToken = serializationService.deserializeJsonAccessToken(new ByteArrayInputStream(
				response.getBody().getBytes()));

		// now try and use the token to access a protected resource.

		// first make sure the resource is actually protected.
		assertNotSame(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/user/message"));

		// now make sure an authorized request is valid.
		HttpHeaders headers = new HttpHeaders();
		headers.set("Authorization", String.format("%s %s", OAuth2AccessToken.BEARER_TYPE, accessToken.getValue()));
		assertEquals(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/user/message", headers));
	}

}
