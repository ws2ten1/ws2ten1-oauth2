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

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.util.Assert;

public class Ws2ten1OAuth2Configurer<H extends HttpSecurityBuilder<H>>
		extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, H> {
	
	private BearerTokenResolver bearerTokenResolver;
	
	private AuthenticationEntryPoint authenticationEntryPoint = new BearerTokenAuthenticationEntryPoint();
	
	private String introspectionUri;
	
	private String introspectionClientId;
	
	private String introspectionClientSecret;
	
	private boolean disableIntrospectionProvider;
	
	private List<AuthenticationProvider> additionalProviders = new ArrayList<>();
	
	
	public Ws2ten1OAuth2Configurer<H> bearerTokenResolver(BearerTokenResolver bearerTokenResolver) {
		Assert.notNull(bearerTokenResolver, "bearerTokenResolver cannot be null");
		this.bearerTokenResolver = bearerTokenResolver;
		return this;
	}
	
	BearerTokenResolver getBearerTokenResolver(H builder) {
		if (this.bearerTokenResolver == null) {
			ApplicationContext context = builder.getSharedObject(ApplicationContext.class);
			if (context.getBeanNamesForType(BearerTokenResolver.class).length > 0) {
				this.bearerTokenResolver = context.getBean(BearerTokenResolver.class);
			} else {
				this.bearerTokenResolver = new DefaultBearerTokenResolver();
			}
		}
		
		return this.bearerTokenResolver;
	}
	
	public Ws2ten1OAuth2Configurer<H> authenticationEntryPoint(AuthenticationEntryPoint entryPoint) {
		Assert.notNull(entryPoint, "entryPoint cannot be null");
		this.authenticationEntryPoint = entryPoint;
		return this;
	}
	
	public Ws2ten1OAuth2Configurer<H> introspectionUri(String introspectionUri) {
		Assert.notNull(introspectionUri, "introspectionUri cannot be null");
		this.introspectionUri = introspectionUri;
		return this;
	}
	
	public Ws2ten1OAuth2Configurer<H> introspectionClientCredentials(String clientId, String clientSecret) {
		Assert.notNull(clientId, "clientId cannot be null");
		Assert.notNull(clientSecret, "clientSecret cannot be null");
		this.introspectionClientId = clientId;
		this.introspectionClientSecret = clientSecret;
		return this;
	}
	
	AuthenticationProvider getProvider() {
		return new Ws2ten1OAuth2IntrospectionAuthenticationProvider(introspectionUri,
				introspectionClientId, introspectionClientSecret);
	}
	
	public Ws2ten1OAuth2Configurer<H> disableIntrospectionProvider() {
		disableIntrospectionProvider = true;
		return this;
	}
	
	public Ws2ten1OAuth2Configurer<H> addAuthenticationProvider(AuthenticationProvider authenticationProvider) {
		additionalProviders.add(authenticationProvider);
		return this;
	}
	
	@Override
	public void configure(H builder) throws Exception {
		BearerTokenResolver bearerTokenResolver = getBearerTokenResolver(builder);
		AuthenticationManagerResolver<HttpServletRequest> resolver =
				request -> builder.getSharedObject(AuthenticationManager.class);
		
		BearerTokenAuthenticationFilter filter = new BearerTokenAuthenticationFilter(resolver);
		filter.setBearerTokenResolver(bearerTokenResolver);
		filter.setAuthenticationEntryPoint(authenticationEntryPoint);
		builder.addFilter(postProcess(filter));
		
		if (disableIntrospectionProvider == false) {
			builder.authenticationProvider(getProvider());
		}
		additionalProviders.forEach(builder::authenticationProvider);
	}
}
