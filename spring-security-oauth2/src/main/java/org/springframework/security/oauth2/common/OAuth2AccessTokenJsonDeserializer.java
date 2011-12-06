package org.springframework.security.oauth2.common;

import java.io.IOException;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.codehaus.jackson.JsonParser;
import org.codehaus.jackson.JsonProcessingException;
import org.codehaus.jackson.JsonToken;
import org.codehaus.jackson.map.DeserializationContext;
import org.codehaus.jackson.map.deser.std.StdDeserializer;


public class OAuth2AccessTokenJsonDeserializer extends StdDeserializer<OAuth2AccessToken> {

    public OAuth2AccessTokenJsonDeserializer() {
        super(OAuth2AccessToken.class);
    }

    @Override
    public OAuth2AccessToken deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException,
            JsonProcessingException {

        String tokenValue = null;
        String tokenType = null;
        String refreshToken = null;
        Long expiresIn = null;
        Boolean expired = null;
        Set<String> scope = null;

        while(jp.nextToken() != JsonToken.END_OBJECT) {
            String name = jp.getCurrentName();
            jp.nextToken();
            if("access_token".equals(name)) {
                tokenValue = jp.getText();
            } else if ("expired".equals(name)) {
                expired = jp.getBooleanValue();
            } else if ("token_type".equals(name)) {
                tokenType = jp.getText();
            } else if ("refresh_token".equals(name)) {
                refreshToken = jp.getText();
            } else if ("expires_in".equals(name)) {
                expiresIn = jp.getLongValue();
            } else if ("scope".equals(name)) {
                String text = jp.getText();
                scope = new HashSet<String>();
                for(String s : text.split(" ")) {
                    scope.add(s);
                }
            } else {
                throw new IllegalArgumentException("Got invalid JSON property '"+name+"'");
            }
        }

        if(expired == null) {
            throw new IllegalArgumentException("Missing expected property 'expired'");
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(tokenValue);
        if(expiresIn != null) {
            accessToken.setExpiration(new Date(System.currentTimeMillis()+(expiresIn*1000)));
        }
        if(refreshToken != null) {
            accessToken.setRefreshToken(new OAuth2RefreshToken(refreshToken));
        }
        accessToken.setTokenType(tokenType);
        accessToken.setScope(scope);

        return accessToken;
    }
}
