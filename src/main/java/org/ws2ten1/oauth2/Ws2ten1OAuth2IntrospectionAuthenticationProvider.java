/*
 * Copyright 2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ws2ten1.oauth2;

import static org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import lombok.extern.slf4j.Slf4j;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.support.BasicAuthenticationInterceptor;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;

/**
 * @see org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationProvider
 */
@Slf4j
public class Ws2ten1OAuth2IntrospectionAuthenticationProvider implements AuthenticationProvider {
	
	/**
	 * {@code scope} - The scopes for the token
	 */
	private static final String SCOPE = "scope";
	
	/**
	 * {@code client_id} - The Client identifier for the token
	 */
	private static final String CLIENT_ID = "client_id";
	
	/**
	 * {@code username} - A human-readable identifier for the resource owner that authorized the token
	 */
	private static final String USERNAME = "username";
	
	/**
	 * {@code exp} - A timestamp indicating when the token expires
	 */
	private static final String EXPIRES_AT = "exp";
	
	/**
	 * {@code iat} - A timestamp indicating when the token was issued
	 */
	private static final String ISSUED_AT = "iat";
	
	/**
	 * {@code nbf} - A timestamp indicating when the token is not to be used before
	 */
	private static final String NOT_BEFORE = "nbf";
	
	/**
	 * {@code aud} - The intended audience for the token
	 */
	private static final String AUDIENCE = "aud";
	
	/**
	 * {@code iss} - The issuer of the token
	 */
	private static final String ISSUER = "iss";
	
	/**
	 * {@code authorities} - The authorities for the user
	 */
	private static final String AUTHORITIES = "authorities";
	
	private URI introspectionUri;
	
	private RestOperations restOperations;
	
	
	/**
	 * Creates a {@code OAuth2IntrospectionAuthenticationProvider} with the provided parameters
	 *
	 * @param introspectionUri The introspection endpoint uri
	 * @param clientId The client id authorized to introspect
	 * @param clientSecret The client secret for the authorized client
	 */
	public Ws2ten1OAuth2IntrospectionAuthenticationProvider(String introspectionUri, String clientId,
			String clientSecret) {
		Assert.notNull(introspectionUri, "introspectionUri cannot be null");
		Assert.notNull(clientId, "clientId cannot be null");
		Assert.notNull(clientSecret, "clientSecret cannot be null");
		
		this.introspectionUri = URI.create(introspectionUri);
		RestTemplate restTemplate = new RestTemplate();
		restTemplate.getInterceptors().add(new BasicAuthenticationInterceptor(clientId, clientSecret));
		this.restOperations = restTemplate;
	}
	
	/**
	 * Creates a {@code OAuth2IntrospectionAuthenticationProvider} with the provided parameters
	 *
	 * @param introspectionUri The introspection endpoint uri
	 * @param restOperations The client for performing the introspection request
	 */
	public Ws2ten1OAuth2IntrospectionAuthenticationProvider(String introspectionUri, RestOperations restOperations) {
		Assert.notNull(introspectionUri, "introspectionUri cannot be null");
		Assert.notNull(restOperations, "restOperations cannot be null");
		
		this.introspectionUri = URI.create(introspectionUri);
		this.restOperations = restOperations;
	}
	
	/**
	 * Introspect and validate the opaque
	 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer Token</a>.
	 *
	 * @param authentication the authentication request object.
	 *
	 * @return A successful authentication
	 * @throws AuthenticationException if authentication failed for some reason
	 */
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (authentication instanceof BearerTokenAuthenticationToken == false) {
			return null;
		}
		
		// introspect
		BearerTokenAuthenticationToken bearer = (BearerTokenAuthenticationToken) authentication;
		TokenIntrospectionSuccessResponse response = introspect(bearer.getToken());
		Map<String, Object> claims = convertClaimsSet(response);
		Instant iat = (Instant) claims.get(ISSUED_AT);
		Instant exp = (Instant) claims.get(EXPIRES_AT);
		String username = (String) claims.get(USERNAME);
		
		// construct token
		OAuth2AccessToken token = new OAuth2AccessToken(TokenType.BEARER, bearer.getToken(), iat, exp);
		Collection<GrantedAuthority> authorities = extractAuthorities(claims);
		AbstractAuthenticationToken result =
				new OAuth2IntrospectionAuthenticationToken(token, claims, authorities, username);
		result.setDetails(bearer.getDetails());
		return result;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean supports(Class<?> authentication) {
		return BearerTokenAuthenticationToken.class.isAssignableFrom(authentication);
	}
	
	private TokenIntrospectionSuccessResponse introspect(String token) {
		return Optional.of(token)
			.map(this::buildRequest)
			.map(this::makeRequest)
			.map(this::adaptToNimbusResponse)
			.map(this::parseNimbusResponse)
			.map(this::castToNimbusSuccess)
			// relying solely on the authorization server to validate this token (not checking 'exp', for example)
			.filter(TokenIntrospectionSuccessResponse::isActive)
			.orElseThrow(() -> new OAuth2AuthenticationException(
					invalidToken("Provided token [" + token + "] isn't active")));
	}
	
	private RequestEntity<MultiValueMap<String, String>> buildRequest(String token) {
		HttpHeaders headers = requestHeaders();
		MultiValueMap<String, String> body = requestBody(token);
		return new RequestEntity<>(body, headers, HttpMethod.POST, this.introspectionUri);
	}
	
	private HttpHeaders requestHeaders() {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON_UTF8));
		return headers;
	}
	
	private MultiValueMap<String, String> requestBody(String token) {
		MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
		body.add("token", token);
		return body;
	}
	
	private ResponseEntity<String> makeRequest(RequestEntity<?> requestEntity) {
		try {
			return this.restOperations.exchange(requestEntity, String.class);
		} catch (Exception ex) { // NOPMD
			throw new OAuth2AuthenticationException(invalidToken(ex.getMessage()), ex);
		}
	}
	
	private HTTPResponse adaptToNimbusResponse(ResponseEntity<String> responseEntity) {
		HTTPResponse response = new HTTPResponse(responseEntity.getStatusCodeValue());
		response.setHeader(HttpHeaders.CONTENT_TYPE, responseEntity.getHeaders().getContentType().toString());
		response.setContent(responseEntity.getBody());
		
		if (response.getStatusCode() != HTTPResponse.SC_OK) {
			throw new OAuth2AuthenticationException(
					invalidToken("Introspection endpoint responded with " + response.getStatusCode()));
		}
		return response;
	}
	
	private TokenIntrospectionResponse parseNimbusResponse(HTTPResponse response) {
		try {
			return TokenIntrospectionResponse.parse(response);
		} catch (Exception ex) { // NOPMD
			throw new OAuth2AuthenticationException(invalidToken(ex.getMessage()), ex);
		}
	}
	
	private TokenIntrospectionSuccessResponse castToNimbusSuccess(TokenIntrospectionResponse introspectionResponse) {
		if (introspectionResponse.indicatesSuccess() == false) {
			throw new OAuth2AuthenticationException(invalidToken("Token introspection failed"));
		}
		return (TokenIntrospectionSuccessResponse) introspectionResponse;
	}
	
	private Map<String, Object> convertClaimsSet(TokenIntrospectionSuccessResponse response) {
		Map<String, Object> claims = response.toJSONObject();
		if (response.getAudience() != null) {
			List<String> audience = response.getAudience().stream()
				.map(Audience::getValue)
				.collect(Collectors.toList());
			claims.put(AUDIENCE, Collections.unmodifiableList(audience));
		}
		if (response.getClientID() != null) {
			claims.put(CLIENT_ID, response.getClientID().getValue());
		}
		if (response.getExpirationTime() != null) {
			Instant exp = response.getExpirationTime().toInstant();
			claims.put(EXPIRES_AT, exp);
		}
		if (response.getIssueTime() != null) {
			Instant iat = response.getIssueTime().toInstant();
			claims.put(ISSUED_AT, iat);
		}
		if (response.getIssuer() != null) {
			claims.put(ISSUER, issuer(response.getIssuer().getValue()));
		}
		if (response.getNotBeforeTime() != null) {
			claims.put(NOT_BEFORE, response.getNotBeforeTime().toInstant());
		}
		if (response.getScope() != null) {
			claims.put(SCOPE, Collections.unmodifiableList(response.getScope().toStringList()));
		}
		
		return claims;
	}
	
	@SuppressWarnings("unchecked")
	private Collection<GrantedAuthority> extractAuthorities(Map<String, Object> claims) {
		Collection<GrantedAuthority> result = new ArrayList<>();
		try {
			Collection<String> authorities = (Collection<String>) claims.get(AUTHORITIES);
			if (authorities != null) {
				authorities.stream()
					.map(SimpleGrantedAuthority::new)
					.forEach(result::add);
			}
		} catch (ClassCastException e) {
			log.warn("Unexpected {} claim", AUTHORITIES, e);
		}
		
		try {
			Collection<String> scopes = (Collection<String>) claims.get(SCOPE);
			if (scopes != null) {
				scopes.stream()
					.map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
					.forEach(result::add);
			}
		} catch (ClassCastException e) {
			log.warn("Unexpected {} claim", SCOPE, e);
		}
		return result;
	}
	
	private URI issuer(String uri) {
		try {
			return URI.create(uri);
		} catch (Exception ex) { // NOPMD
			throw new OAuth2AuthenticationException(invalidToken("Invalid " + ISSUER + " value: " + uri), ex);
		}
	}
	
	private static BearerTokenError invalidToken(String message) {
		return new BearerTokenError("invalid_token", HttpStatus.UNAUTHORIZED, message,
				"https://tools.ietf.org/html/rfc7662#section-2.2");
	}
}
