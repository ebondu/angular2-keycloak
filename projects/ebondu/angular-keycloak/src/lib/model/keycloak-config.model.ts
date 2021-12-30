/*
 * Copyright 2018 ebondu and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { InjectionToken } from '@angular/core';

export const KEYCLOAK_JSON_PATH = new InjectionToken('keycloakJsonPath');
export const KEYCLOAK_INIT_OPTIONS = new InjectionToken('keycloakOptions');
export const KEYCLOAK_CONF = new InjectionToken('keycloakConfiguration');

export enum KeycloakAdapterName {CORDOVA = 'cordova', DEFAULT = 'default', ANY = 'any'}

export enum KeycloakOnLoad {LOGIN_REQUIRED = 'login-required', CHECK_SSO = 'check-sso'}

export enum KeycloakResponseMode {QUERY = 'query', FRAGMENT = 'fragment'}

export enum KeycloakResponseType {CODE = 'code', ID_TOKEN = 'id_token token', CODE_ID_TOKEN = 'code id_token token'}

export enum KeycloakFlow {STANDARD = 'standard', IMPLICIT = 'implicit', HYBRID = 'hybrid'}


export interface KeycloakInitOptions {

  useNonce?: boolean;

  /**
   * Allows to use different adapter:
   *
   * - {string} default - using browser api for redirects
   * - {string} cordova - using cordova plugins
   * - {function} - allows to provide custom function as adapter.
   */
  adapter?: KeycloakAdapterName;

  /**
   * Specifies an action to do on load.
   */
  onLoad?: KeycloakOnLoad;

  /**
   * Set an initial value for the token.
   */
  token?: string;

  /**
   * Set an initial value for the refresh token.
   */
  refreshToken?: string;

  /**
   * Set an initial value for the id token (only together with `token` or
   * `refreshToken`).
   */
  idToken?: string;

  /**
   * Set an initial value for skew between local time and Keycloak server in
   * seconds (only together with `token` or `refreshToken`).
   */
  timeSkew?: number;

  /**
   * Set to enable/disable monitoring login state.
   * @default true
   */
  checkLoginIframe?: boolean;

  /**
   * Set the interval to check login state (in seconds).
   * @default 5
   */
  checkLoginIframeInterval?: number;

  /**
   * Set the redirect uri to silent check login state.
   */
  silentCheckSsoRedirectUri?: string;

  /**
   * Set the OpenID Connect response mode to send to Keycloak upon login.
   * @default fragment After successful authentication Keycloak will redirect
   *                   to JavaScript application with OpenID Connect parameters
   *                   added in URL fragment. This is generally safer and
   *                   recommended over query.
   */
  responseMode?: KeycloakResponseMode;

  /**
   * Set the OpenID Connect flow.
   * @default standard
   */
  flow?: KeycloakFlow;
}

export interface KeycloakLoginOptions {
  /**
   * Undocumented.
   */
  scope?: string;

  /**
   * Specifies the uri to redirect to after login.
   */
  redirectUri?: string;

  /**
   * By default the login screen is displayed if the user is not logged into
   * Keycloak. To only authenticate to the application if the user is already
   * logged in and not display the login page if the user is not logged in, set
   * this option to `'none'`. To always require re-authentication and ignore
   * SSO, set this option to `'login'`.
   */
  prompt?: 'none' | 'login';

  /**
   * If value is `'register'` then user is redirected to registration page,
   * otherwise to login page.
   */
  action?: 'register';

  /**
   * Used just if user is already authenticated. Specifies maximum time since
   * the authentication of user happened. If user is already authenticated for
   * longer time than `'maxAge'`, the SSO is ignored and he will need to
   * authenticate again.
   */
  maxAge?: number;

  /**
   * Used to pre-fill the username/email field on the login form.
   */
  loginHint?: string;

  /**
   * Used to tell Keycloak which IDP the user wants to authenticate with.
   */
  idpHint?: string;

  /**
   * Sets the 'ui_locales' query param in compliance with section 3.1.2.1
   * of the OIDC 1.0 specification.
   */
  locale?: string;

  /**
   * Specifies the desired Keycloak locale for the UI.  This differs from
   * the locale param in that it tells the Keycloak server to set a cookie and update
   * the user's profile to a new preferred locale.
   */
  kcLocale?: string;
}

export interface KeycloakConfiguration {
  realm: string;
  authServerUrl: string;
  clientId: string;
  clientSecret?: string;
}
