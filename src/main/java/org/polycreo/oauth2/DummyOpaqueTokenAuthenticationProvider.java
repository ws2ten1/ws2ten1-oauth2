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
package org.polycreo.oauth2;

import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.EXPIRES_AT;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.ISSUED_AT;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

@Slf4j
public class DummyOpaqueTokenAuthenticationProvider implements AuthenticationProvider {
	
	private static final BearerTokenError DEFAULT_INVALID_TOKEN = new BearerTokenError("invalid_token",
			HttpStatus.UNAUTHORIZED, "An error occurred while attempting to introspect the token: Invalid token",
			"https://tools.ietf.org/html/rfc7662#section-2.2");
	
	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
	
	
	public static String createDummyToken(String username, String[] authorities, String[] scopes, long iat, long exp) {
		TokenData data = new TokenData(username, authorities, scopes, iat, exp);
		try {
			String tokenData = OBJECT_MAPPER.writeValueAsString(data);
			return Base64.getEncoder().encodeToString(tokenData.getBytes(StandardCharsets.UTF_8));
		} catch (JsonProcessingException e) {
			throw new AssertionError(e);
		}
	}
	
	private static TokenData decode(String token) {
		try {
			String tokenData = new String(Base64.getDecoder().decode(token), StandardCharsets.UTF_8);
			return OBJECT_MAPPER.readValue(tokenData, TokenData.class);
		} catch (JsonProcessingException e) {
			throw new IllegalArgumentException(e);
		}
	}
	
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (authentication instanceof BearerTokenAuthenticationToken == false) {
			return null;
		}
		BearerTokenAuthenticationToken bearerTokenAuthentication = (BearerTokenAuthenticationToken) authentication;
		
		try {
			TokenData token = decode(bearerTokenAuthentication.getToken());
			Collection<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList(token.getAuthorities());
			Set<String> scope = new HashSet<>(Arrays.asList(token.getScopes()));
			Instant iat = Instant.ofEpochMilli(token.getIat());
			Instant exp = Instant.ofEpochMilli(token.getIat() + token.getExp());
			
			Map<String, Object> attributes = new HashMap<>();
			attributes.put("username", token.getUsername());
			attributes.put("scope", scope);
			attributes.put(ISSUED_AT, iat);
			attributes.put(EXPIRES_AT, exp);
			
			// construct token
			OAuth2AuthenticatedPrincipal principal =
					new DefaultOAuth2AuthenticatedPrincipal(token.getUsername(), attributes, authorities);
			OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
					bearerTokenAuthentication.getToken(), iat, exp, scope);
			BearerTokenAuthentication result = new BearerTokenAuthentication(principal, accessToken, authorities);
			result.setDetails(bearerTokenAuthentication.getDetails());
			return result;
		} catch (IllegalArgumentException | ArrayIndexOutOfBoundsException e) {
			// New exception is thrown in catch block, original stack trace may be lost
			log.error("Failed to parse dummy token: {}", bearerTokenAuthentication.getToken(), e);
			throw new OAuth2AuthenticationException(DEFAULT_INVALID_TOKEN); // NOPMD
		}
	}
	
	@Override
	public boolean supports(Class<?> authentication) {
		return BearerTokenAuthenticationToken.class.isAssignableFrom(authentication);
	}
	
	
	@Data
	@AllArgsConstructor
	@NoArgsConstructor
	private static class TokenData {
		
		private String username;
		
		private String[] authorities;
		
		private String[] scopes;
		
		private long iat;
		
		private long exp;
	}
}
