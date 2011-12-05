package org.springframework.security.oauth2.common;

import java.io.IOException;

import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.JsonGenerator;
import org.codehaus.jackson.map.SerializerProvider;
import org.codehaus.jackson.map.ser.std.SerializerBase;
import org.codehaus.jackson.type.JavaType;

public class JacksonSerializer extends SerializerBase<OAuth2AccessToken>{

    public JacksonSerializer(Class<?> t, boolean dummy) {
        super(t, dummy);
    }

    public JacksonSerializer(JavaType type) {
        super(type);
    }

    protected JacksonSerializer(Class<OAuth2AccessToken> t) {
        super(t);
    }

    @Override
    public void serialize(OAuth2AccessToken token, JsonGenerator jgen, SerializerProvider provider) throws IOException,
            JsonGenerationException {
        jgen.writeStartObject();
        jgen.writeStringField("", token.getValue());
        jgen.writeStringField("", token.getTokenType());
        jgen.writeStringField("", token.getValue());
        jgen.writeEndObject();
    }
}
