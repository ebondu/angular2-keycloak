/*
 * Copyright 2023 ebondu and/or its affiliates
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

import { Inject, Injectable, Injector, Optional, PLATFORM_ID } from '@angular/core';
import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';
import { BehaviorSubject, EMPTY, Observable, of } from 'rxjs';

import { v4 as uuidv4 } from 'uuid';
import { DefaultAdapter } from '../adapter/keycloak.adapter.default';
import { LocalStorage } from '../storage/keycloak.storage.local';
import { URIParser } from '../util/keycloak.utils.URIParser';
import { Token } from '../util/keycloak.utils.token';
import {
  KEYCLOAK_CONF,
  KEYCLOAK_INIT_OPTIONS,
  KEYCLOAK_JSON_PATH,
  KeycloakAdapterName,
  KeycloakConfiguration,
  KeycloakFlow,
  KeycloakInitOptions,
  KeycloakOnLoad,
  KeycloakResponseMode,
  KeycloakResponseType
} from '../model/keycloak-config.model';
import { filter, map, mergeMap, switchMap, tap } from 'rxjs/operators';
import { CordovaAdapter } from '../adapter/keycloak.adapter.cordova';
import { CookieStorage } from '../storage/keycloak.storage.cookie';
import { KeycloakCheckLoginIframe } from '../util/keycloak.utils.check-login-iframe';
import { KeycloakSilentCheckLoginIframe } from '../util/keycloak.utils.silent-check-login-iframe';
import { KeycloakCheck3pCookiesIframe } from '../util/keycloak.utils.check-3pCookies-iframe';
import { isPlatformBrowser } from '@angular/common';

/**
 * Keycloak core classes to manage tokens with a keycloak server.
 *
 * Used for login, logout, register, account management, profile.
 * Provide Angular Observable objects for initialization, authentication, token expiration.
 *
 */

@Injectable({
  providedIn: 'root'
})
export class KeycloakService {

  public initializedObs: Observable<boolean>;
  public initializedAuthzObs: Observable<boolean>;
  public authenticationObs: Observable<boolean>;
  public tokenExpiredObs: Observable<boolean>;
  public authenticationErrorObs: Observable<any>;
  // tokens
  public accessToken: string;
  public tokenParsed: any;
  public sessionId: any;
  // Observables
  private initBS: BehaviorSubject<boolean>;
  private initAuthzBS: BehaviorSubject<boolean>;
  private authenticationsBS: BehaviorSubject<boolean>;
  private tokenExpiredBS: BehaviorSubject<boolean>;
  private authenticationErrorBS: BehaviorSubject<any>;
  private refreshToken: string;
  private refreshTokenParsed: any;
  private rpt: string;
  private idToken: string;
  private idTokenParsed: any;
  // keycloak conf
  private umaConfig: any;
  private adapter;
  private callbackStorage;
  private responseType;
  private timeSkew;
  private tokenTimeoutHandle;
  private subject: any;
  private realmAccess;
  private resourceAccess;
  private loginIframe: KeycloakCheckLoginIframe;

  get http() {
    return this.injector.get(HttpClient);
  }

  constructor(private injector: Injector,
              @Optional() @Inject(KEYCLOAK_JSON_PATH) private configUrl: string,
              @Optional() @Inject(KEYCLOAK_CONF) public keycloakConfig: KeycloakConfiguration,
              @Inject(KEYCLOAK_INIT_OPTIONS) public initOptions: KeycloakInitOptions,
              @Inject(PLATFORM_ID) private platformId) {

    this.initBS = new BehaviorSubject(false);
    this.initializedObs = this.initBS.asObservable();

    this.initAuthzBS = new BehaviorSubject(false);
    this.initializedAuthzObs = this.initAuthzBS.asObservable();

    this.authenticationsBS = new BehaviorSubject(false);
    this.authenticationObs = this.authenticationsBS.asObservable();

    this.tokenExpiredBS = new BehaviorSubject<boolean>(false);
    this.tokenExpiredObs = this.tokenExpiredBS.asObservable();

    this.authenticationErrorBS = new BehaviorSubject<any>(null);
    this.authenticationErrorObs = this.authenticationErrorBS.asObservable();
    // console.log('Keycloak service created with init options and configuration file', initOptions, configUrl);

    if (!globalThis.isSecureContext) {
      console.warn('Keycloak JS must be used in a \'secure context\' to function properly as it relies on browser APIs that are otherwise not available');
    }

    if (!isPlatformBrowser(platformId)) {
      // console.log('Keycloak service init only available on browser platform');
      this.initBS.next(false);
    } else if (this.configUrl) {
      this.http.get(this.configUrl).subscribe(config => {
        this.keycloakConfig = {
          authServerUrl: config['auth-server-url'],
          realm: config['realm'],
          clientId: config['resource'],
          clientSecret: (config['credentials'] || {})['secret']
        };
        // console.log('Conf loaded', this.keycloakConfig);
        this.initService();
      }, error => {
        // console.log('Unable to load keycloak.json', error);
        this.initBS.next(false);
      });
    } else if (keycloakConfig) {
      this.initService();
    } else {
      // console.log('Keycloak service init fails : no keycloak.json or configuration provided');
      this.initBS.next(false);
    }

    this.initializedObs.pipe(filter(initialized => !!initialized)).subscribe(next => {
      // console.log('Keycloak initialized, initializing authz service', this);
      if (next) {
        const url = this.keycloakConfig.authServerUrl + '/realms/' + this.keycloakConfig.realm + '/.well-known/uma2-configuration';
        this.http.get(url).subscribe(authz => {
          // console.log('Authz configuration file loaded, continuing authz');
          this.umaConfig = authz;
          this.initAuthzBS.next(true);
        }, error => {
          // console.log('unable to get uma file', error);
          this.initAuthzBS.next(false);
        });
      }
    });
  }

  public parseCallback(url: string): any {
    const oauth: any = URIParser.parseUri(url, this.initOptions.responseMode);
    const state: string = oauth.state;
    const oauthState = this.callbackStorage.get(state);

    if (oauthState && (oauth.code || oauth.error || oauth.access_token || oauth.id_token)) {
      oauth.valid = true;
      oauth.redirectUri = oauthState.redirectUri;
      oauth.storedNonce = oauthState.nonce;
      oauth.prompt = oauthState.prompt;
      oauth.pkceCodeVerifier = oauthState.pkceCodeVerifier;
      if (oauth.fragment) {
        oauth.newUrl += '#' + oauth.fragment;
      }
      return oauth;
    }
  }

  public processCallback(oauth: any): Observable<boolean> {
    return new Observable<boolean>((observer: any) => {
      const code = oauth.code;
      const error = oauth.error;
      const prompt = oauth.prompt;
      const timeLocal = new Date().getTime();

      if (error) {
        const errorData = {error: error, error_description: oauth.error_description};
        this.authenticationErrorBS.next(errorData);
        if (prompt !== 'none') {
          // console.log('error while processing callback');
          observer.next(false);
        }
        return;
      } else if ((this.initOptions.flow !== KeycloakFlow.STANDARD) && (oauth.access_token || oauth.id_token)) {
        this.authSuccess(oauth.access_token, null, oauth.id_token, true, timeLocal, oauth);
        observer.next(true);
      }

      if ((this.initOptions.flow !== KeycloakFlow.IMPLICIT) && code) {

        let withCredentials = false;
        const url = this.getRealmUrl() + '/protocol/openid-connect/token';
        let params: HttpParams = new HttpParams();
        params = params.set('code', code);
        params = params.set('grant_type', 'authorization_code');

        let headers = new HttpHeaders();
        headers = headers.set('Content-type', 'application/x-www-form-urlencoded');

        if (this.keycloakConfig.clientId && this.keycloakConfig.clientSecret) {
          headers = headers.set('Authorization', 'Basic ' + btoa(this.keycloakConfig.clientId + ':' + this.keycloakConfig.clientSecret));
          withCredentials = true;
        } else {
          params = params.set('client_id', this.keycloakConfig.clientId);
        }
        params = params.set('redirect_uri', oauth.redirectUri);

        if (oauth.pkceCodeVerifier) {
          params = params.set('code_verifier', oauth.pkceCodeVerifier);
        }

        const options = {headers: headers, withCredentials: withCredentials};
        const body = null;
        this.http.post(url, params, options).subscribe(token => {

          this.authSuccess(
            token['access_token'],
            token['refresh_token'],
            token['id_token'],
            this.initOptions.flow === KeycloakFlow.STANDARD,
            timeLocal,
            oauth);
          this.authenticationsBS.next(true);
          observer.next(true);
        }, (errorToken => {
          this.authenticationErrorBS.next({error: errorToken, error_description: 'unable to get token from server'});
          // console.log('Unable to get token', errorToken);
          observer.next(false);
        }));
      }
    });
  }

  login(options: any) {
    return this.adapter.login(options);
  }


  // ###################################
  // #######   Keycloak methods   ######
  // ###################################

  logout(options: any) {
    return this.adapter.logout(options);
  }

  updateToken(minValidity: number): Observable<string> {

    minValidity = minValidity || 5;

    if (!this.isTokenExpired(minValidity)) {
      // console.log('token still valid');
      return of(this.accessToken);
    } else {
      if (this.isRefreshTokenExpired(5)) {
        this.login(this.keycloakConfig);
        return EMPTY;
      } else {
        // console.log('refreshing token');
        let params: HttpParams = new HttpParams();
        params = params.set('grant_type', 'refresh_token');
        params = params.set('refresh_token', this.refreshToken);

        const url = this.getRealmUrl() + '/protocol/openid-connect/token';
        let headers = new HttpHeaders({'Content-type': 'application/x-www-form-urlencoded'});

        let withCredentials = false;
        if (this.keycloakConfig.clientId && this.keycloakConfig.clientSecret) {
          headers = headers.append(
            'Authorization',
            'Basic ' + btoa(this.keycloakConfig.clientId + ': ' + this.keycloakConfig.clientSecret));
          withCredentials = true;
        } else {
          params = params.set('client_id', this.keycloakConfig.clientId);
        }

        let timeLocal = new Date().getTime();
        return this.http.post(url, params, {headers: headers, withCredentials: withCredentials}).pipe(
          map((token: any) => {
            timeLocal = (timeLocal + new Date().getTime()) / 2;
            this.setToken(token['access_token'], token['refresh_token'], token['id_token'], true);
            this.timeSkew = Math.floor(timeLocal / 1000) - this.tokenParsed.iat;
            return token['access_token'];
          })
        );
      }
    }
  }

  register(options: any) {
    return this.adapter.register(options);
  }

  accountManagement(options: any) {
    return this.adapter.accountManagement(options);
  }

  loadChangePassword(options: any) {
    return this.adapter.passwordManagement(options);
  }

  loadUserProfile(): Observable<any> {
    // need to refresh token to get account-console as aud
    let paramsToSend: HttpParams = new HttpParams();
    let headersToSend = new HttpHeaders();
    headersToSend = headersToSend.set('Content-type', 'application/x-www-form-urlencoded');
    paramsToSend = paramsToSend.set('client_id', this.keycloakConfig.clientId);
    paramsToSend = paramsToSend.set('grant_type', 'refresh_token');
    paramsToSend = paramsToSend.set('refresh_token', this.refreshToken);
    headersToSend = headersToSend.set('Authorization', 'bearer ' + this.accessToken);
    const url = this.getRealmUrl() + '/account/';
    return this.http.post(this.umaConfig?.token_endpoint, paramsToSend, {withCredentials: false, headers: headersToSend})
      .pipe(mergeMap((token: any) => {
        const headers = new HttpHeaders({'Authorization': 'bearer ' + token.access_token});
        return this.http.get(url, {headers: headers, withCredentials: false});
      }));
  }

  updateUserProfile(profile: any): Observable<any> {
    // need to refresh token to get account-console as aud
    let paramsToSend: HttpParams = new HttpParams();
    let headersToSend = new HttpHeaders();
    headersToSend = headersToSend.set('Content-type', 'application/x-www-form-urlencoded');
    paramsToSend = paramsToSend.set('client_id', this.keycloakConfig.clientId);
    paramsToSend = paramsToSend.set('grant_type', 'refresh_token');
    paramsToSend = paramsToSend.set('refresh_token', this.refreshToken);
    headersToSend = headersToSend.set('Authorization', 'bearer ' + this.accessToken);
    const url = this.getRealmUrl() + '/account/';
    return this.http.post(this.umaConfig?.token_endpoint, paramsToSend, {withCredentials: true, headers: headersToSend})
      .pipe(mergeMap((token: any) => {
        const headers = new HttpHeaders({'Authorization': 'bearer ' + token.access_token});
        return this.http.post(url, profile, {headers: headers, withCredentials: false});
      }));
  }

  createDeleteAccountUrl(options?: any): string {
      const state = uuidv4();
      const nonce = this.initOptions.useNonce ? uuidv4() : null;
      // const redirectUri = this.getRealmUrl() + '/account/#/personal-info';
      const redirectUri = this.adapter.redirectUri({});
      const callback: {state, nonce, redirectUri, pkceCodeVerifier? } = {
        state: state,
        nonce: nonce,
        redirectUri: redirectUri
      };

      const action = 'auth';

      let url = this.getRealmUrl()
        + '/protocol/openid-connect/' + action
        + '?client_id=' + encodeURIComponent(this.keycloakConfig.clientId)
        + '&redirect_uri=' + encodeURIComponent(redirectUri)
        + '&state=' + encodeURIComponent(state)
        + '&response_mode=' + encodeURIComponent(this.initOptions.responseMode)
        + '&response_type=' + encodeURIComponent(this.responseType)
        + '&scope=' + encodeURIComponent('openid')
        + '&kc_action=' + encodeURIComponent('delete_account');

      if (options.useNonce) {
        url += '&nonce=' + encodeURIComponent(nonce);
      }

      let codeVerifier;
      const pkceMethod = this.initOptions.pkceMethod;
      codeVerifier = Token.generateCodeVerifier(96);
      callback.pkceCodeVerifier = codeVerifier;
      const pkceChallenge = Token.generatePkceChallenge(pkceMethod, codeVerifier);
      url += '&code_challenge=' + pkceChallenge;
      url += '&code_challenge_method=' + pkceMethod;

      this.callbackStorage.add(callback);
      return url;
  }

  createUpdateProfileUrl(options?: any): string {
    const state = uuidv4();
    const nonce = this.initOptions.useNonce ? uuidv4() : null;
    const redirectUri = this.adapter.redirectUri({});
    const callback: {state, nonce, redirectUri, pkceCodeVerifier? } = {
      state: state,
      nonce: nonce,
      redirectUri: redirectUri
    };

    const action = 'auth';

    let url = this.getRealmUrl()
      + '/protocol/openid-connect/' + action
      + '?client_id=' + encodeURIComponent(this.keycloakConfig.clientId)
      + '&redirect_uri=' + encodeURIComponent(redirectUri)
      + '&state=' + encodeURIComponent(state)
      + '&response_mode=' + encodeURIComponent(this.initOptions.responseMode)
      + '&response_type=' + encodeURIComponent(this.responseType)
      + '&scope=' + encodeURIComponent('openid')
      + '&kc_action=' + encodeURIComponent('UPDATE_PROFILE');

    if (options.useNonce) {
      url += '&nonce=' + encodeURIComponent(nonce);
    }

    let codeVerifier;
    const pkceMethod = this.initOptions.pkceMethod;
    codeVerifier = Token.generateCodeVerifier(96);
    callback.pkceCodeVerifier = codeVerifier;
    const pkceChallenge = Token.generatePkceChallenge(pkceMethod, codeVerifier);
    url += '&code_challenge=' + pkceChallenge;
    url += '&code_challenge_method=' + pkceMethod;

    this.callbackStorage.add(callback);
    return url;
  }

  changePassword(): string {
    const state = uuidv4();
    const nonce = this.initOptions.useNonce ? uuidv4() : null;
    const redirectUri = this.adapter.redirectUri({});
    const callback: {state, nonce, redirectUri, pkceCodeVerifier? } = {
      state: state,
      nonce: nonce,
      redirectUri: redirectUri
    };

    const action = 'auth';

    let url = this.getRealmUrl()
      + '/protocol/openid-connect/' + action
      + '?client_id=' + encodeURIComponent(this.keycloakConfig.clientId)
      + '&redirect_uri=' + encodeURIComponent(redirectUri)
      + '&state=' + encodeURIComponent(state)
      + '&response_mode=' + encodeURIComponent(this.initOptions.responseMode)
      + '&response_type=' + encodeURIComponent(this.responseType)
      + '&scope=' + encodeURIComponent('openid')
      + '&kc_action=' + encodeURIComponent('UPDATE_PASSWORD');

    if (this.initOptions.useNonce) {
      url += '&nonce=' + encodeURIComponent(nonce);
    }

    let codeVerifier;
    const pkceMethod = this.initOptions.pkceMethod;
    codeVerifier = Token.generateCodeVerifier(96);
    callback.pkceCodeVerifier = codeVerifier;
    const pkceChallenge = Token.generatePkceChallenge(pkceMethod, codeVerifier);
    url += '&code_challenge=' + pkceChallenge;
    url += '&code_challenge_method=' + pkceMethod;

    this.callbackStorage.add(callback);
    return url;
  }

  loadUserInfo(): Observable<any> {
    const url = this.getRealmUrl() + '/protocol/openid-connect/userinfo';
    const headers = new HttpHeaders({'Accept': 'application/json', 'Authorization': 'bearer ' + this.accessToken});
    return this.http.get(url, {headers: headers});
  }

  hasRealmRole(role: string): boolean {
    const access = this.realmAccess;
    return !!access && access.roles.indexOf(role) >= 0;
  }

  hasResourceRole(role: string, resource: string): boolean {
    if (!this.resourceAccess) {
      return false;
    }
    const access: any = this.resourceAccess[resource || this.keycloakConfig.clientId];
    return !!access && access.roles.indexOf(role) >= 0;
  }

  isTokenExpired(minValidity: number): boolean {
    if (!this.tokenParsed || (!this.refreshToken && this.initOptions.flow !== KeycloakFlow.IMPLICIT)) {
      throw new Error('Not authenticated');
    }

    let expiresIn = this.tokenParsed['exp'] - (new Date().getTime() / 1000) + this.timeSkew;
    if (minValidity) {
      expiresIn -= minValidity;
    }

    return expiresIn < 0;
  }

  isRefreshTokenExpired(minValidity: number): boolean {
    if (!this.tokenParsed || (!this.refreshToken && this.initOptions.flow !== KeycloakFlow.IMPLICIT)) {
      throw new Error('Not authenticated');
    }

    let expiresIn = this.refreshTokenParsed['exp'] - (new Date().getTime() / 1000) + this.timeSkew;
    if (minValidity) {
      expiresIn -= minValidity;
    }
    return expiresIn < 0;
  }

  /**
   * This method enables client applications to better integrate with resource servers protected by a Keycloak
   * policy enforcer.
   *
   * In this case, the resource server will respond with a 401 status code and a WWW-Authenticate header holding the
   * necessary information to ask a Keycloak server for authorization data using both UMA and Entitlement protocol,
   * depending on how the policy enforcer at the resource server was configured.
   */
  authorize(wwwAuthenticateHeader: string): Observable<boolean> {
    return this.initializedAuthzObs.pipe(
      filter(initialized => !!initialized),
      switchMap(() => {
        return this.processAuthz(wwwAuthenticateHeader);
      })
    );
  }

  /**
   * Obtains all entitlements from a Keycloak Server based on a give resourceServerId.
   */
  entitlement(resourceServerId: string): Observable<boolean> {
    const url = this.keycloakConfig.authServerUrl + '/realms/' + this.keycloakConfig.realm + '/authz/entitlement/' + resourceServerId;
    const headers = new HttpHeaders({'Authorization': 'Bearer ' + this.accessToken});
    return this.http.get(url, {headers: headers, withCredentials: false})
      .pipe(
        tap((token: any) => {
          this.rpt = token.rpt;
        })
      );
  }

  public clearToken(initOptions: any) {
    if (this.accessToken) {
      this.setToken(null, null, null, true);
      this.authenticationsBS.next(false);
      if (this.initOptions.onLoad === KeycloakOnLoad.LOGIN_REQUIRED) {
        this.login(initOptions);
      }
    }
  }

  // ###################################
  // #######    Token methods     ######
  // ###################################

  createLoginUrl(options: any): string {
    const state = uuidv4();
    const nonce = this.initOptions.useNonce ? uuidv4() : null;

    let redirectUri = this.adapter.redirectUri(options);
    if (options && options.prompt) {
      redirectUri += (redirectUri.indexOf('?') === -1 ? '?' : '&') + 'prompt=' + options.prompt;
    }

    const callback: {state, nonce, redirectUri, pkceCodeVerifier? } = {
      state: state,
      nonce: nonce,
      redirectUri: redirectUri,
    };

    let action = 'auth';
    if (options && options.action === 'register') {
      action = 'registrations';
    }

    const scope = (options && options.scope) ? 'openid ' + options.scope : 'openid';

    let url = this.getRealmUrl()
      + '/protocol/openid-connect/' + action
      + '?client_id=' + encodeURIComponent(this.keycloakConfig.clientId)
      + '&redirect_uri=' + encodeURIComponent(redirectUri)
      + '&state=' + encodeURIComponent(state)
      + '&response_mode=' + encodeURIComponent(this.initOptions.responseMode)
      + '&response_type=' + encodeURIComponent(this.responseType)
      + '&scope=' + encodeURIComponent(scope);

    if (options.useNonce) {
      url += '&nonce=' + encodeURIComponent(nonce);
    }

    if (options && options.prompt) {
      url += '&prompt=' + encodeURIComponent(options.prompt);
    }

    if (options && options.maxAge) {
      url += '&max_age=' + encodeURIComponent(options.maxAge);
    }

    if (options && options.loginHint) {
      url += '&login_hint=' + encodeURIComponent(options.loginHint);
    }

    if (options && options.idpHint) {
      url += '&kc_idp_hint=' + encodeURIComponent(options.idpHint);
    }

    if (options && options.locale) {
      url += '&ui_locales=' + encodeURIComponent(options.locale);
    }

    if (options && options.acr) {
      url += '&claims=' + encodeURIComponent(JSON.stringify({
        id_token: {
          acr: options.acr
        }
      }));
    }

    let codeVerifier;
    if ((options && options.pkceMethod) || !!this.initOptions.pkceMethod) {
      const pkceMethod = !!options.pkceMethod ? options.pkceMethod : this.initOptions.pkceMethod;
      codeVerifier = Token.generateCodeVerifier(96);
      callback.pkceCodeVerifier = codeVerifier;
      const pkceChallenge = Token.generatePkceChallenge(pkceMethod, codeVerifier);
      url += '&code_challenge=' + pkceChallenge;
      url += '&code_challenge_method=' + pkceMethod;
    }

    this.callbackStorage.add(callback);
    return url;
  }

  createLogoutUrl(options: any): string {
    const url = this.getRealmUrl()
      + '/protocol/openid-connect/logout'
      + '?post_logout_redirect_uri=' + encodeURIComponent(this.adapter.redirectUri(options, false))
      + '&id_token_hint=' + encodeURIComponent(this.idToken)
    ;

    return url;
  }

  createRegisterUrl(options: any): string {
    if (!options) {
      options = {};
    }
    options.action = 'register';
    return this.createLoginUrl(options);
  }

  createAccountUrl(options: any): string {
    const url = this.getRealmUrl()
      + '/account'
      + '?referrer=' + encodeURIComponent(this.keycloakConfig.clientId)
      + '&referrer_uri=' + encodeURIComponent(this.adapter.redirectUri(options));

    return url;
  }

  // ###################################
  // #######     URLs methods     ######
  // ###################################

  createChangePasswordUrl(options: any): string {
    const url = this.getRealmUrl()
      + '/account/password'
      + '?referrer=' + encodeURIComponent(this.keycloakConfig.clientId)
      + '&referrer_uri=' + encodeURIComponent(this.adapter.redirectUri(options));

    return url;
  }

  getRealmUrl(): string {
    if (this.keycloakConfig.authServerUrl.charAt(this.keycloakConfig.authServerUrl.length - 1) === '/') {
      return this.keycloakConfig.authServerUrl + 'realms/' + encodeURIComponent(this.keycloakConfig.realm);
    } else {
      return this.keycloakConfig.authServerUrl + '/realms/' + encodeURIComponent(this.keycloakConfig.realm);
    }
  }

  private initService() {

    // Adapter
    if (this.initOptions.adapter === KeycloakAdapterName.CORDOVA) {
      this.adapter = new CordovaAdapter(this);
    } else if (this.initOptions.adapter === KeycloakAdapterName.DEFAULT) {
      this.adapter = new DefaultAdapter(this);
    } else {
      if (window[<any>'cordova']) {
        this.adapter = new CordovaAdapter(this);
      } else {
        this.adapter = new DefaultAdapter(this);
      }
    }

    // Storage
    try {
      this.callbackStorage = new LocalStorage();
    } catch (e) {
      // console.log('Unable to create a local storage, using cookie storage');
      this.callbackStorage = new CookieStorage();
    }

    // default values;
    if (!this.initOptions.flow) {
      this.initOptions.flow = KeycloakFlow.STANDARD;
    }

    if (!this.initOptions.responseMode) {
      this.initOptions.responseMode = KeycloakResponseMode.FRAGMENT;
    }
    switch (this.initOptions.flow) {
      case KeycloakFlow.STANDARD:
        this.responseType = KeycloakResponseType.CODE;
        break;
      case KeycloakFlow.IMPLICIT:
        this.responseType = KeycloakResponseType.ID_TOKEN;
        break;
      case KeycloakFlow.HYBRID:
        this.responseType = KeycloakResponseType.CODE_ID_TOKEN;
        break;
      default:
        // console.log('Invalid value for flow');
    }

    if (this.initOptions.pkceMethod) {
      if (this.initOptions.pkceMethod !== 'S256') {
        throw new Error('Invalid value for pkceMethod');
      }
    }

    // Callback
    // console.log('processing callback ', window.location.href);
    const callback = this.parseCallback(window.location.href);
    if (callback) {
      window.history.replaceState({}, null, callback.newUrl);
      this.processCallback(callback).subscribe(callbackProcessed => {
        this.initBS.next(true);
      });
    } else if (this.initOptions) {
      if (this.initOptions.token || this.initOptions.refreshToken) {
        this.setToken(this.initOptions.token, this.initOptions.refreshToken, this.initOptions.idToken, false);
        this.timeSkew = this.initOptions.timeSkew || 0;
        this.initBS.next(true);
      } else if (this.initOptions.onLoad) {
        switch (this.initOptions.onLoad) {
          case KeycloakOnLoad.CHECK_SSO:
            if (this.initOptions.silentCheckSsoRedirectUri) {
              new KeycloakCheck3pCookiesIframe(this).supportedObs.subscribe(supported => {
                if (supported) {
                  const silentCheckIframe = new KeycloakSilentCheckLoginIframe(
                    this,
                    this.initOptions.silentCheckSsoRedirectUri
                  );
                  // console.log('silent check Iframe', silentCheckIframe);
                } else if (supported != null && !supported && this.initOptions.silentCheckSsoFallback) {
                  // console.log('Falling back to check-sso with redirect');
                  this.login({
                    prompt: 'none',
                    redirectUri: window.location.href
                  });
                }
              });
            }
            this.initBS.next(true);
            break;
          case KeycloakOnLoad.LOGIN_REQUIRED:
            this.login({});
            break;
          default:
            // console.log('Invalid value for onLoad');
        }
      } else {
        this.initBS.next(true);
      }
    } else {
      this.initBS.next(true);
    }
  }

  private processAuthz(wwwAuthenticateHeader: string): Observable<boolean> {
    return new Observable<boolean>((observer: any) => {
      if (wwwAuthenticateHeader.indexOf('UMA') !== -1) {
        const params = wwwAuthenticateHeader.split(',');

        let paramsToSend: HttpParams = new HttpParams();
        let headers = new HttpHeaders();
        headers = headers.set('Content-type', 'application/x-www-form-urlencoded');

        const formData: FormData = new FormData();
        for (let i = 0; i < params.length; i++) {
          const param = params[i].split('=');

          if (param[0] === 'ticket') {
            const ticket = param[1].substring(1, param[1].length - 1).trim();

            headers = headers.set('Authorization', 'Bearer ' + this.accessToken);
            paramsToSend = paramsToSend.set('ticket', ticket);
            paramsToSend = paramsToSend.set('grant_type', 'urn:ietf:params:oauth:grant-type:uma-ticket');
            paramsToSend = paramsToSend.set('rpt', this.accessToken);
            paramsToSend = paramsToSend.set('client_id', this.keycloakConfig.clientId);
          }
        }
        this.http.post(this.umaConfig?.token_endpoint, paramsToSend, {withCredentials: false, headers: headers}).subscribe(
          (token: any) => {

            // console.log('Authorization granted by the server.');
            // Token retrieved
            this.accessToken = token.access_token;
            this.refreshToken = token.refresh_token;
            observer.next(true);

          }, error => {

            if (error.status === 403) {
              // console.error('Authorization request was denied by the server.');
              observer.next(false);
            } else {
              // console.error('Could not obtain authorization data from server.');
              observer.next(false);
            }
          }
        );

      } else if (wwwAuthenticateHeader.indexOf('KC_ETT') !== -1) {
        const params = wwwAuthenticateHeader.substring('KC_ETT'.length).trim().split(',');
        let clientId: string = null;

        for (let i = 0; i < params.length; i++) {
          const param = params[i].split('=');

          if (param[0] === 'realm') {
            clientId = param[1].substring(1, param[1].length - 1).trim();
          }
        }
        this.entitlement(clientId).subscribe(entitlement => {
          observer.next(true);
        });
      }
    });
  }

  private authSuccess(accessToken: string, refreshToken: string, idToken: string, fulfillPromise: any, timeLocal: any, oauth: any) {
    const passedTimeLocal = (timeLocal + new Date().getTime()) / 2;
    this.setToken(accessToken, refreshToken, idToken, true);

    if (this.initOptions.useNonce && ((this.tokenParsed && this.tokenParsed.nonce !== oauth.storedNonce) ||
      (this.refreshTokenParsed && this.refreshTokenParsed.nonce !== oauth.storedNonce) ||
      (this.idTokenParsed && this.idTokenParsed.nonce !== oauth.storedNonce))) {
      this.authenticationErrorBS.next({error: 'invalid_nonce', error_description: 'the provided nonce does not match stored nonce'});
      this.clearToken({});
    } else {
      this.timeSkew = Math.floor(passedTimeLocal / 1000) - this.tokenParsed.iat;
      if (fulfillPromise) {
        this.authenticationsBS.next(true);
      }
    }
  }

  private setToken(accessToken: string, refreshToken: string, idToken: string, useTokenTime: boolean) {
    if (this.tokenTimeoutHandle) {
      clearTimeout(this.tokenTimeoutHandle);
      this.tokenTimeoutHandle = null;
    }

    if (accessToken) {
      this.accessToken = accessToken;
      this.refreshToken = refreshToken;
      this.tokenParsed = Token.decodeToken(accessToken);
      this.refreshTokenParsed = Token.decodeToken(refreshToken);
      this.sessionId = this.tokenParsed.session_state;
      this.authenticationsBS.next(true);
      this.subject = this.tokenParsed.sub;
      this.realmAccess = this.tokenParsed.realm_access;
      this.resourceAccess = this.tokenParsed.resource_access;
      const start = useTokenTime ? this.tokenParsed.iat : (new Date().getTime() / 1000);
      const expiresIn = this.tokenParsed.exp - start;
      this.tokenExpiredBS.next(false);
      this.tokenTimeoutHandle = setTimeout(() => this.tokenExpiredBS.next(true), expiresIn * 1000);
    } else {
      delete this.accessToken;
      delete this.tokenParsed;
      delete this.subject;
      delete this.realmAccess;
      delete this.resourceAccess;
    }

    if (refreshToken) {
      this.refreshToken = refreshToken;
      this.refreshTokenParsed = Token.decodeToken(refreshToken);
    } else {
      delete this.refreshToken;
      delete this.refreshTokenParsed;
    }

    if (idToken) {
      this.idToken = idToken;
      this.idTokenParsed = Token.decodeToken(idToken);
    } else {
      delete this.idToken;
      delete this.idTokenParsed;
    }
  }

  // getProtectedResource(resourceSet: string): Observable<any> {
  //   let headers = new HttpHeaders();
  //   // headers = headers.set('Authorization', 'Bearer ' + this.accessToken);
  //   // headers = headers.set('Content-type', 'text/plain');
  //   // headers = headers.set('Accept', '*/*');
  //   return this.http.get(
  //     `${this.keycloakConfig.authServerUrl}/realms/${this.keycloakConfig.realm}/authz/protection/resource_set/${resourceSet}`,
  //     {withCredentials: true});
  // }
}
