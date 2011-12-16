package org.springframework.security.oauth2.common.exceptions;

import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import org.codehaus.jackson.map.annotate.JsonDeserialize;
import org.codehaus.jackson.map.annotate.JsonSerialize;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jackson.OAuth2ExceptionJsonDeserializer;
import org.springframework.security.oauth2.jackson.OAuth2ExceptionJsonSerializer;

/**
 * Base exception for OAuth 2 authentication exceptions.
 *
 * @author Ryan Heaton
 */
@JsonSerialize(using=OAuth2ExceptionJsonSerializer.class)
@JsonDeserialize(using=OAuth2ExceptionJsonDeserializer.class)
public class OAuth2Exception extends AuthenticationException {

	private Map<String, String> additionalInformation = null;

	public OAuth2Exception(String msg, Throwable t) {
		super(msg, t);
	}

	public OAuth2Exception(String msg) {
		super(msg);
	}

	/**
	 * The OAuth2 error code.
	 *
	 * @return The OAuth2 error code.
	 */
	public String getOAuth2ErrorCode() {
		return "invalid_request";
	}

	/**
	 * The HTTP error code associated with this error.
	 *
	 * @return The HTTP error code associated with this error.
	 */
	public int getHttpErrorCode() {
		return 400;
	}

	/**
	 * Get any additional information associated with this error.
	 *
	 * @return Additional information, or null if none.
	 */
	public Map<String, String> getAdditionalInformation() {
		return this.additionalInformation;
	}

	/**
	 * Add some additional information with this OAuth error.
	 *
	 * @param key The key.
	 * @param value The value.
	 */
	public void addAdditionalInformation(String key, String value) {
		if (this.additionalInformation == null) {
			this.additionalInformation = new TreeMap<String, String>();
		}

		this.additionalInformation.put(key, value);

	}

	/**
	 * Creates the appropriate subclass of OAuth2Exception given the errorCode.
	 * @param errorCode
	 * @param errorMessage
	 * @return
	 */
	public static OAuth2Exception create(String errorCode, String errorMessage) {
		if (errorMessage == null) {
			errorMessage = errorCode == null ? "OAuth Error" : errorCode;
		}
		if ("invalid_client".equals(errorCode)) {
			return new InvalidClientException(errorMessage);
		}
		else if ("unauthorized_client".equals(errorCode)) {
			return new UnauthorizedClientException(errorMessage);
		}
		else if ("invalid_grant".equals(errorCode)) {
			return new InvalidGrantException(errorMessage);
		}
		else if ("invalid_scope".equals(errorCode)) {
			return new InvalidScopeException(errorMessage);
		}
		else if ("invalid_token".equals(errorCode)) {
			return new InvalidTokenException(errorMessage);
		}
		else if ("invalid_request".equals(errorCode)) {
			return new InvalidRequestException(errorMessage);
		}
		else if ("redirect_uri_mismatch".equals(errorCode)) {
			return new RedirectMismatchException(errorMessage);
		}
		else if ("unsupported_grant_type".equals(errorCode)) {
			return new UnsupportedGrantTypeException(errorMessage);
		}
		else if ("unsupported_response_type".equals(errorCode)) {
			return new UnsupportedResponseTypeException(errorMessage);
		}
		else if ("access_denied".equals(errorCode)) {
			return new UserDeniedAuthorizationException(errorMessage);
		}
		else {
			return new OAuth2Exception(errorMessage);
		}
	}

	/**
	 * Creates an {@link OAuth2Exception} from a Map<String,String>.
	 *
	 * @param errorParams
	 * @return
	 */
	public static OAuth2Exception valueOf(Map<String, String> errorParams) {
		String errorCode = errorParams.get("error");
		String errorMessage = errorParams.containsKey("error_description") ? errorParams.get("error_description")
				: null;
		OAuth2Exception ex = create(errorCode,errorMessage);
		Set<Map.Entry<String, String>> entries = errorParams.entrySet();
		for (Map.Entry<String, String> entry : entries) {
			String key = entry.getKey();
			if (!"error".equals(key) && !"error_description".equals(key)) {
				ex.addAdditionalInformation(key, entry.getValue());
			}
		}

		return ex;
	}
}
