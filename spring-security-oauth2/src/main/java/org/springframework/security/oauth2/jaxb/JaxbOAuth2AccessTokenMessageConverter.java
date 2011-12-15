/*
 * Copyright 2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.oauth2.jaxb;

import java.io.IOException;
import java.util.Date;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.MarshalException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.UnmarshalException;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.Result;
import javax.xml.transform.Source;

import org.springframework.http.HttpHeaders;
import org.springframework.http.converter.HttpMessageConversionException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.converter.xml.AbstractXmlHttpMessageConverter;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;

public class JaxbOAuth2AccessTokenMessageConverter extends AbstractXmlHttpMessageConverter<OAuth2AccessToken> {
	private final Class<OAuth2AccessToken> clazz;

	private final Unmarshaller unmarshaller;

	private final Marshaller marshaller;

	public JaxbOAuth2AccessTokenMessageConverter() throws JAXBException {
		this.clazz = OAuth2AccessToken.class;
		JAXBContext context = JAXBContext.newInstance(JaxbOAuth2AccessToken.class);
		this.unmarshaller = context.createUnmarshaller();
		this.marshaller = context.createMarshaller();
		this.marshaller.setProperty("jaxb.fragment", Boolean.TRUE);
	}

	@Override
	protected OAuth2AccessToken readFromSource(Class<? extends OAuth2AccessToken> clazz, HttpHeaders headers,
			Source source) throws IOException {
		try {
			JAXBElement<? extends JaxbOAuth2AccessToken> jaxbElement = unmarshaller.unmarshal(source, JaxbOAuth2AccessToken.class);
			return convert(jaxbElement.getValue());
		}
		catch (UnmarshalException ex) {
			throw new HttpMessageNotReadableException("Could not unmarshal to [" + clazz + "]: " + ex.getMessage(), ex);
		}
		catch (JAXBException ex) {
			throw new HttpMessageConversionException("Could not instantiate JAXBContext: " + ex.getMessage(), ex);
		}
	}

	@Override
	protected void writeToResult(OAuth2AccessToken accessToken, HttpHeaders headers, Result result) throws IOException {
		JaxbOAuth2AccessToken convertedAccessToken = convert(accessToken);
		try {
			marshaller.marshal(convertedAccessToken, result);
		}
		catch (MarshalException ex) {
			throw new HttpMessageNotWritableException("Could not marshal [" + accessToken + "]: " + ex.getMessage(), ex);
		}
		catch (JAXBException ex) {
			throw new HttpMessageConversionException("Could not instantiate JAXBContext: " + ex.getMessage(), ex);
		}
	}

	protected JaxbOAuth2AccessToken convert(OAuth2AccessToken accessToken) {
		JaxbOAuth2AccessToken jaxbAccessToken = new JaxbOAuth2AccessToken();
		jaxbAccessToken.setAccessToken(accessToken.getValue());
		jaxbAccessToken.setExpriation(accessToken.getExpiration());
		OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
		if(refreshToken != null) {
			jaxbAccessToken.setRefreshToken(refreshToken.getValue());
		}
		return jaxbAccessToken;
	}

	protected OAuth2AccessToken convert(JaxbOAuth2AccessToken jaxbAccessToken) {
		OAuth2AccessToken accessToken = new OAuth2AccessToken(jaxbAccessToken.getAccessToken());
		String refreshToken = jaxbAccessToken.getRefreshToken();
		if(refreshToken != null) {
			accessToken.setRefreshToken(new OAuth2RefreshToken(refreshToken));
		}
		Date expiration = jaxbAccessToken.getExpiration();
		if(expiration != null) {
			accessToken.setExpiration(expiration);
		}
		return accessToken;
	}

	@Override
	protected boolean supports(Class<?> clazz) {
		return this.clazz.equals(clazz);
	}
}
