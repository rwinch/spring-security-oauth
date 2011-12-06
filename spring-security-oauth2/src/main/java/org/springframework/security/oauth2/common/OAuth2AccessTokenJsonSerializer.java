package org.springframework.security.oauth2.common;

import java.io.IOException;
import java.util.Date;
import java.util.Set;

import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.JsonGenerator;
import org.codehaus.jackson.map.SerializerProvider;
import org.codehaus.jackson.map.ser.std.SerializerBase;
import org.springframework.util.Assert;

public final class OAuth2AccessTokenJsonSerializer extends SerializerBase<OAuth2AccessToken>{

    public OAuth2AccessTokenJsonSerializer() {
        super(OAuth2AccessToken.class);
    }

    @Override
    public void serialize(OAuth2AccessToken token, JsonGenerator jgen, SerializerProvider provider) throws IOException,
            JsonGenerationException {
        jgen.writeStartObject();
        jgen.writeStringField("access_token", token.getValue());
        jgen.writeBooleanField("expired", token.isExpired());
        jgen.writeStringField("token_type", token.getTokenType());
        OAuth2RefreshToken refreshToken = token.getRefreshToken();
        if(refreshToken != null) {
            jgen.writeStringField("refresh_token", refreshToken.getValue());
        }
        Date expiration = token.getExpiration();
        if(expiration != null) {
            long now = System.currentTimeMillis();
            jgen.writeNumberField("expires_in", (expiration.getTime() - now) / 1000);
        }
        Set<String> scope = token.getScope();
        if(scope != null && !scope.isEmpty()) {
            StringBuffer scopes = new StringBuffer();
            for(String s : scope) {
                Assert.hasLength(s,"Scopes cannot be null or empty. Got "+scope+"");
                scopes.append(s);
                scopes.append(" ");
            }
            jgen.writeStringField("scope", scopes.substring(0,scopes.length()-1));
        }
        jgen.writeEndObject();
    }
}
