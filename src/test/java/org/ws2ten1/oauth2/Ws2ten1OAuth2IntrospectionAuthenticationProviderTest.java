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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestOperations;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class Ws2ten1OAuth2IntrospectionAuthenticationProviderTest {
	
	private static final String INTROSPECTION_URI = "https://example.com/introspect";
	
	private static final String ACTIVE_RESPONSE_BODY = "{\"active\": true}";
	
	private static final String INACTIVE_RESPONSE_BODY = "{\"active\": false}";
	
	private static final MultiValueMap<String, String> HEADERS;
	
	static {
		HEADERS = new HttpHeaders();
		HEADERS.set(HttpHeaders.CONTENT_TYPE, "application/json");
	}
	
	@Captor
	ArgumentCaptor<RequestEntity<String>> captor;
	
	@Mock
	RestOperations restOperations;
	
	private Ws2ten1OAuth2IntrospectionAuthenticationProvider sut;
	
	
	@Before
	public void setUp() throws Exception {
		sut = new Ws2ten1OAuth2IntrospectionAuthenticationProvider(INTROSPECTION_URI, restOperations);
	}
	
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
		ResponseEntity<String> response = new ResponseEntity<>(ACTIVE_RESPONSE_BODY, HEADERS, HttpStatus.OK);
		when(restOperations.exchange(any(), eq(String.class))).thenReturn(response);
		Authentication authentication = new BearerTokenAuthenticationToken("example-token");
		// exercise
		Authentication actual = sut.authenticate(authentication);
		// verify
		assertThat(actual).isNotNull();
		assertThat(actual.isAuthenticated()).isTrue();
		
		verify(restOperations).exchange(captor.capture(), eq(String.class));
		RequestEntity<String> request = captor.getValue();
		assertThat(request.getMethod()).isEqualTo(HttpMethod.POST);
		assertThat(request.getUrl()).isEqualTo(URI.create(INTROSPECTION_URI));
	}
	
	@Test
	public void testAuthenticate_inactive_OAuth2AuthenticationException() {
		// setup
		ResponseEntity<String> response = new ResponseEntity<>(INACTIVE_RESPONSE_BODY, HEADERS, HttpStatus.OK);
		when(restOperations.exchange(any(), eq(String.class))).thenReturn(response);
		Authentication authentication = new BearerTokenAuthenticationToken("example-token");
		// exercise
		Throwable actual = catchThrowable(() -> sut.authenticate(authentication));
		// verify
		assertThat(actual)
			.isInstanceOf(OAuth2AuthenticationException.class)
			.hasMessage("Provided token [example-token] isn't active");
		
		verify(restOperations).exchange(captor.capture(), eq(String.class));
		RequestEntity<String> request = captor.getValue();
		assertThat(request.getMethod()).isEqualTo(HttpMethod.POST);
		assertThat(request.getUrl()).isEqualTo(URI.create(INTROSPECTION_URI));
	}
}
