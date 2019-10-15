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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import java.time.Instant;
import java.util.Set;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class DummyOpaqueTokenAuthenticationProviderTest {
	
	@InjectMocks
	DummyOpaqueTokenAuthenticationProvider sut;
	
	
	@Test
	public void testSupports_BearerTokenAuthenticationToken_true() {
		// exercise
		boolean actual = sut.supports(BearerTokenAuthenticationToken.class);
		// verify
		assertThat(actual).isTrue();
	}
	
	@Test
	public void testSupports_UsernamePasswordAuthenticationToken_false() {
		// exercise
		boolean actual = sut.supports(UsernamePasswordAuthenticationToken.class);
		// verify
		assertThat(actual).isFalse();
	}
	
	@Test
	public void testAuthenticate_active_authenticated() {
		// setup
		long now = Instant.now().toEpochMilli();
		String token = "example-user:ROLE_ADMIN,ROLE_USER:openid,profile:" + now + ":300000";
		Authentication authentication = new BearerTokenAuthenticationToken(token);
		// exercise
		Authentication actual = sut.authenticate(authentication);
		// verify
		assertThat(actual).isNotNull();
		assertThat(actual.isAuthenticated()).isTrue();
		assertThat(actual.getName()).isEqualTo("example-user");
		assertThat(actual.getAuthorities()).extracting(GrantedAuthority::getAuthority)
			.containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_USER");
		assertThat(actual.getPrincipal()).isInstanceOfSatisfying(OAuth2AuthenticatedPrincipal.class, principal -> {
			Set<String> scope = principal.getAttribute("scope");
			assertThat(scope).containsExactlyInAnyOrder("openid", "profile");
		});
		assertThat(actual.getCredentials()).isInstanceOfSatisfying(OAuth2AccessToken.class, accessToken -> {
			assertThat(accessToken.getTokenType()).isEqualTo(TokenType.BEARER);
			assertThat(accessToken.getScopes()).containsExactlyInAnyOrder("openid", "profile");
			assertThat(accessToken.getIssuedAt()).isEqualTo(Instant.ofEpochMilli(now));
			assertThat(accessToken.getExpiresAt()).isEqualTo(Instant.ofEpochMilli(now + 300000));
			assertThat(accessToken.getTokenValue()).isEqualTo(token);
		});
		assertThat(actual).isInstanceOfSatisfying(BearerTokenAuthentication.class, actualToken -> {
			assertThat(actualToken.getToken()).isEqualTo(actual.getCredentials());
			assertThat(actualToken.getTokenAttributes())
				.containsOnlyKeys("username", "scope", "iat", "exp")
				.containsEntry("username", "example-user");
		});
	}
	
	@Test
	public void testAuthenticate_inactive_OAuth2AuthenticationException() {
		// setup
		Authentication authentication = new BearerTokenAuthenticationToken("example-token");
		// exercise
		Throwable actual = catchThrowable(() -> sut.authenticate(authentication));
		// verify
		assertThat(actual)
			.isInstanceOf(OAuth2AuthenticationException.class)
			.hasMessage("An error occurred while attempting to introspect the token: Invalid token");
	}
}
