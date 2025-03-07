/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

/**
 * Constants denoting JWT claims as specified here:
 * https://tools.ietf.org/html/rfc7519#section-4
 */
public final class TokenClaims {

	private TokenClaims() {
		throw new IllegalStateException("Utility class");
	}

	/**
	 * @deprecated Use {@link Token#getIssuer()} instead.
	 */
	@Deprecated
	public static final String ISSUER = "iss";
	/**
	 * @deprecated Use {@link Token#getIssuer()} instead.
	 */
	@Deprecated
	public static final String IAS_ISSUER = "ias_iss";
	public static final String EXPIRATION = "exp";
	public static final String AUDIENCE = "aud";
	public static final String NOT_BEFORE = "nbf";
	public static final String SUBJECT = "sub"; // to be used instead of client id
	public static final String USER_NAME = "user_name";
	public static final String GIVEN_NAME = "given_name";
	public static final String FAMILY_NAME = "family_name";
	public static final String EMAIL = "email";
	/**
	 * IAS applications provide this attribute if the user was authenticated via an
	 * OIDC trust to an IAS tenant and if the user actually has a user UUID. This is
	 * true if the user physically exists in the IAS user store and IAS is not a
	 * pure proxy which simply forwards all information from the corporate IdP.
	 */
	public static final String SAP_GLOBAL_SCIM_ID = "scim_id";
	public static final String SAP_GLOBAL_USER_ID = "user_uuid";
	public static final String SAP_GLOBAL_ZONE_ID = "zone_uuid"; // tenant GUID
	public static final String GROUPS = "groups"; // scim groups
	public static final String AUTHORIZATION_PARTY = "azp"; // Authorization party contains OAuth client identifier
	public static final String CNF = "cnf"; // X509 certificate ("cnf" (confirmation)) claim
	public static final String CNF_X5T = "x5t#S256"; // X509 certificate thumbprint confirmation method

	public final class XSUAA {

		private XSUAA() {
		}

		public static final String ORIGIN = "origin";
		public static final String GRANT_TYPE = "grant_type"; // OAuth grant type used for token creation
		public static final String ZONE_ID = "zid"; // tenant GUID -> SAP_GLOBAL_ZONE_ID
		/**
		 * @deprecated Use {@link Token#getClientId} instead.
		 */
		@Deprecated
		public static final String CLIENT_ID = "cid"; // avoid using directly, make use of Token#getClientId() instead
		public static final String SCOPES = "scope"; // list of scopes including app id, e.g. "my-app!t123.Display"
		public static final String ISSUED_AT = "iat";
		public static final String EXTERNAL_ATTRIBUTE = "ext_attr";
		public static final String EXTERNAL_ATTRIBUTE_ZDN = "zdn"; // subdomain
		// new with SECAUTH-806
		public static final String EXTERNAL_ATTRIBUTE_SUBACCOUNTID = "subaccountid";
		public static final String EXTERNAL_ATTRIBUTE_ENHANCER = "enhancer";
		public static final String XS_USER_ATTRIBUTES = "xs.user.attributes";
		public static final String TRUSTED_CLIENT_ID_SUFFIX = "trustedclientidsuffix";
	}

}
