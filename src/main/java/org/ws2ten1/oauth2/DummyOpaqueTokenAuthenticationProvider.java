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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;

public class DummyOpaqueTokenAuthenticationProvider implements AuthenticationProvider {
	
	public static String BAD_TOKEN = "bad-token";
	
	
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (authentication instanceof BearerTokenAuthenticationToken == false) {
			return null;
		}
		BearerTokenAuthenticationToken bearer = (BearerTokenAuthenticationToken) authentication;
		
		if (bearer.getToken().equals(BAD_TOKEN)) {
			throw new OAuth2AuthenticationException(invalidToken("Bad token"));
		}
		
		String username = "dummy.user";
		
		Map<String, Object> attributes = new HashMap<>();
		attributes.put("username", username);
		attributes.put("scope", Arrays.asList("openid", "profile"));
		
		// construct token
		OAuth2AccessToken token = new OAuth2AccessToken(TokenType.BEARER, bearer.getToken(), null, null);
		AbstractAuthenticationToken result = new OAuth2IntrospectionAuthenticationToken(
				token, attributes, AuthorityUtils.NO_AUTHORITIES, username);
		result.setDetails(bearer.getDetails());
		return result;
	}
	
	@Override
	public boolean supports(Class<?> authentication) {
		return BearerTokenAuthenticationToken.class.isAssignableFrom(authentication);
	}
	
	private static BearerTokenError invalidToken(String message) {
		return new BearerTokenError("invalid_token",
				HttpStatus.UNAUTHORIZED, message,
				"https://tools.ietf.org/html/rfc7662#section-2.2");
	}
}
