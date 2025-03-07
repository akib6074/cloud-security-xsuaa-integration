/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.extractor;

import com.sap.cloud.security.xsuaa.token.XsuaaToken;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.HashSet;

import static org.assertj.core.api.Assertions.assertThat;

public class LocalAuthoritiesExtractorTest {
	LocalAuthoritiesExtractor cut;
	XsuaaToken token;
	Collection<String> scopes = new HashSet<>();

	@Before
	public void setup() {
		cut = new LocalAuthoritiesExtractor("appId!1234");

		token = Mockito.mock(XsuaaToken.class);
		scopes.add("appId!1234.Scope1");
		scopes.add("appId!1234.Scope2");
		scopes.add("appId2!888.Scope1");
		scopes.add("appId2!777.Scope3");
		Mockito.when(token.getScopes()).thenReturn(scopes);
	}

	@Test
	public void extractLocalScopes() {
		assertThat(cut.getAuthorities(token)).containsExactlyInAnyOrder(
				new SimpleGrantedAuthority("Scope1"),
				new SimpleGrantedAuthority("Scope2"));
	}

}