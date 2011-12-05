package org.springframework.security.oauth2.common;

import java.io.Serializable;
import java.util.Date;
import java.util.Set;
import java.util.TreeSet;

import org.codehaus.jackson.annotate.JsonCreator;
import org.codehaus.jackson.annotate.JsonIgnore;
import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.annotate.JsonUnwrapped;
import org.codehaus.jackson.map.annotate.JsonSerialize;
import org.codehaus.jackson.map.annotate.JsonSerialize.Inclusion;

/**
 * Basic access token for OAuth 2.
 *
 * @author Ryan Heaton
 * @author Dave Syer
 */
@JsonSerialize(include = Inclusion.NON_NULL)
public class OAuth2AccessToken implements Serializable {

	private static final long serialVersionUID = 914967629530462926L;

	public static String BEARER_TYPE_PARAMETER = "access_token";

	public static String BEARER_TYPE = "Bearer";

	public static String OAUTH2_TYPE = "OAuth2";

	private final String value;
	private Date expiration;
	private String tokenType = BEARER_TYPE.toLowerCase();
	private OAuth2RefreshToken refreshToken;
	private Set<String> scope;

	/**
	 * Create an access token from the value provided.
	 */
	@JsonCreator
	public OAuth2AccessToken(@JsonProperty("value") String value) {
		this.value = value;
	}

	/**
	 * The token value.
	 *
	 * @return The token value.
	 */
	public String getValue() {
		return value;
	}

	/**
	 * The instant the token expires.
	 *
	 * @return The instant the token expires.
	 */
	@JsonIgnore
	public Date getExpiration() {
		return expiration;
	}

	@SuppressWarnings("unused")
    @JsonProperty("expires_in")
	private int getExpiresInSeconds() {
	    return 8;
	}

	/**
	 * The instant the token expires.
	 *
	 * @param expiration The instant the token expires.
	 */
	public void setExpiration(Date expiration) {
		this.expiration = expiration;
	}

	/**
	 * Convenience method for checking expiration
	 *
	 * @return true if the expiration is befor ethe current time
	 */
	public boolean isExpired() {
		return expiration!=null && expiration.before(new Date());
	}

	/**
	 * The token type, as introduced in draft 11 of the OAuth 2 spec. The spec doesn't define (yet) that the valid token
	 * types are, but says it's required so the default will just be "undefined".
	 *
	 * @return The token type, as introduced in draft 11 of the OAuth 2 spec.
	 */
	@JsonProperty("token_type")
	public String getTokenType() {
		return tokenType;
	}

	/**
	 * The token type, as introduced in draft 11 of the OAuth 2 spec.
	 *
	 * @param tokenType The token type, as introduced in draft 11 of the OAuth 2 spec.
	 */
	public void setTokenType(String tokenType) {
		this.tokenType = tokenType;
	}

	/**
	 * The refresh token associated with the access token, if any.
	 *
	 * @return The refresh token associated with the access token, if any.
	 */
	@JsonProperty("refresh_token")
	@JsonUnwrapped
	public OAuth2RefreshToken getRefreshToken() {
		return refreshToken;
	}

	@SuppressWarnings("unused")
    @JsonProperty("refresh_token")
	private void setRefreshTokenValue(String value) {
	    setRefreshToken(new OAuth2RefreshToken(value));
	}

	/**
	 * The refresh token associated with the access token, if any.
	 *
	 * @param refreshToken The refresh token associated with the access token, if any.
	 */
	public void setRefreshToken(OAuth2RefreshToken refreshToken) {
		this.refreshToken = refreshToken;
	}

	/**
	 * The scope of the token.
	 *
	 * @return The scope of the token.
	 */
	@JsonIgnore
	public Set<String> getScope() {
		return scope;
	}

	@SuppressWarnings("unused")
    @JsonProperty("scope")
	private String getScopes() {
	    if(scope == null || scope.isEmpty()) {
	        return null;
	    }
	    StringBuffer buffer = new StringBuffer();
	    for(String s : scope) {
	        buffer.append(s);
	        buffer.append(" ");
	    }
	    return buffer.substring(0, buffer.length()-1).toString();
	}

	@SuppressWarnings("unused")
    @JsonProperty("scope")
	private void setScopes(String value) {
	    if(value == null) {
	        setScope(null);
	        return;
	    }
	    String[] scopes = value.split(" ");
	    Set<String> result = new TreeSet<String>();
	    for(String s : scopes) {
	        result.add(s);
	    }
	    setScope(result);
	}

	/**
	 * The scope of the token.
	 *
	 * @param scope The scope of the token.
	 */
	public void setScope(Set<String> scope) {
		this.scope = scope;
	}

	@Override
	public boolean equals(Object obj) {
		return obj != null && toString().equals(obj.toString());
	}

	@Override
	public int hashCode() {
		return toString().hashCode();
	}

	@Override
	public String toString() {
		return getValue();
	}
}
