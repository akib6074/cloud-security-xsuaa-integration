/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.token.authentication;

import com.sap.cloud.security.token.Token;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.util.Assert;
import java.lang.reflect.Field;

import java.util.Collection;
import java.util.Objects;

/**
 * Internal class used to expose the {@link Token} implementation as the
 * standard Principal for Spring Security Jwt handling. <br>
 * <br>
 *
 * The {@link Token} instance is accessible via the Security Context:
 *
 * {@code (Token)SecurityContextHolder.getContext().getAuthentication().getPrincipal();}
 *
 * @see Token
 * @see XsuaaTokenAuthorizationConverter
 *
 */
public class AuthenticationToken extends JwtAuthenticationToken {
	private static final long serialVersionUID = -3779129534612771294L;
	private final Token token;

	/**
	 * Creates
	 * 
	 * @param jwt
	 *            Spring Security's representation of the jwt token
	 * @param grantedAuthorities
	 *            the authorities that were extracted by Spring Security frameworks
	 *            and potentially modified by the application.
	 *
	 */
	public AuthenticationToken(Jwt jwt, Collection<GrantedAuthority> grantedAuthorities) {
		super(jwt, grantedAuthorities);
		Assert.notNull(getToken().getTokenValue(), "Jwt needs to provide a token value.");
		this.token = Token.create(getToken().getTokenValue());
	}

	@Override
	public Object getPrincipal() {
		return token;
	}

	@Override
	public String getName() {
		return token.getPrincipal().getName(); // TODO is that correct?
	}

	@Override
	public boolean equals(Object obj) {
		if (compareObjects(this,obj)) {
			System.out.println("--------------------------------------1");
			return true;
		}
		if (obj != null && this.getClass() != obj.getClass()) {
			System.out.println("--------------------------------------2");
			return false;
		}
		if (obj == null) {
			System.out.println("--------------------------------------3");
			return false;
		}
		AuthenticationToken that = (AuthenticationToken) obj;
		System.out.println("--------------------------------------4");
		System.out.println(this.token);
		System.out.println(that.token);
		return compareObjects(this.token,that.token) && compareObjects(this.getAuthorities(), that.getAuthorities());
	}

	public static boolean compareObjects(Object obj1, Object obj2) {
		if (obj1 == null || obj2 == null) {
			return obj1 == obj2;
		}
		if (!obj1.getClass().equals(obj2.getClass())) {
			return false;
		}
		Field[] fields = obj1.getClass().getDeclaredFields();
		for (Field field : fields) {
			field.setAccessible(true);
			try {
				Object value1 = field.get(obj1);
				Object value2 = field.get(obj2);
				if (value1 == null || value2 == null) {
					if (value1 != value2) {
						return false;
					}
				} else if (!value1.equals(value2)) {
					return false;
				}
			} catch (IllegalAccessException e) {
				// handle exception
			}
		}
		return true;
	}

	@Override
	public int hashCode() {
		return Objects.hash(super.hashCode(), getToken());
	}

}
