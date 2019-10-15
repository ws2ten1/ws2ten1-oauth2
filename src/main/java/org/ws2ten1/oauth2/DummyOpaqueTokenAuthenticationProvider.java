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

import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.EXPIRES_AT;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.ISSUED_AT;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

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

@Slf4j
public class DummyOpaqueTokenAuthenticationProvider implements AuthenticationProvider {
	
	private static final BearerTokenError DEFAULT_INVALID_TOKEN = new BearerTokenError("invalid_token",
			HttpStatus.UNAUTHORIZED, "An error occurred while attempting to introspect the token: Invalid token",
			"https://tools.ietf.org/html/rfc7662#section-2.2");
	
	
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (authentication instanceof BearerTokenAuthenticationToken == false) {
			return null;
		}
		BearerTokenAuthenticationToken bearerTokenAuthentication = (BearerTokenAuthenticationToken) authentication;
		String token = bearerTokenAuthentication.getToken();
		try {
			String[] split = token.split(":");
			String username = split[0];
			Collection<GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(split[1]);
			Set<String> scope = new HashSet<>(Arrays.asList(split[2].split(",")));
			Instant iat = Instant.ofEpochMilli(Long.parseLong(split[3]));
			Instant exp = Instant.ofEpochMilli(Long.parseLong(split[3]) + Long.parseLong(split[4]));
			
			Map<String, Object> attributes = new HashMap<>();
			attributes.put("username", username);
			attributes.put("scope", scope);
			attributes.put(ISSUED_AT, iat);
			attributes.put(EXPIRES_AT, exp);
			
			// construct token
			OAuth2AuthenticatedPrincipal principal =
					new DefaultOAuth2AuthenticatedPrincipal(username, attributes, authorities);
			OAuth2AccessToken accessToken =
					new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, token, iat, exp, scope);
			BearerTokenAuthentication result = new BearerTokenAuthentication(principal, accessToken, authorities);
			result.setDetails(bearerTokenAuthentication.getDetails());
			return result;
		} catch (ArrayIndexOutOfBoundsException | NumberFormatException e) {
			// New exception is thrown in catch block, original stack trace may be lost
			log.error("Failed to parse dummy token: {}", token, e);
			throw new OAuth2AuthenticationException(DEFAULT_INVALID_TOKEN); // NOPMD
		}
	}
	
	@Override
	public boolean supports(Class<?> authentication) {
		return BearerTokenAuthenticationToken.class.isAssignableFrom(authentication);
	}
}
