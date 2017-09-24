/*
 * Copyright 2017 ebondu and/or its affiliates
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

import { Injectable, Inject, PLATFORM_ID } from '@angular/core';
import { isPlatformBrowser, isPlatformServer } from '@angular/common';
import {
  Http,
  Headers,
  RequestOptionsArgs,
  URLSearchParams
} from '@angular/http';
import { DefaultAdapter } from '../adapters/keycloak.adapter.default';
import { Observable, BehaviorSubject } from 'rxjs/Rx';
import 'rxjs/operator/map';
import { CordovaAdapter } from '../adapters/keycloak.adapter.cordova';
import { LocalStorage } from '../storage/keycloak.storage.local';
import { CookieStorage } from '../storage/keycloak.storage.cookie';
import { URIParser } from '../utils/keycloak.utils.URIParser';
import { LoginIframe } from '../utils/keycloak.utils.loginIframe';
import { Token } from '../utils/keycloak.utils.token';
import { Lock } from '../utils/keycloak.utils.singleton';
import { UUID } from 'angular2-uuid';

/**
 * Keycloak core classes to manage tokens with a keycloak server.
 *
 * Used for login, logout, register, account management, profile.
 * Provide Angular Observable objects for initialization, authentication, token expiration and errors.
 *
 */

declare var window: any;

@Injectable()
export class Keycloak {
  // Keycloak state subjects
  static initializedBehaviourSubject: BehaviorSubject<boolean> = new BehaviorSubject(false);
  static initializingBehaviourSubject: BehaviorSubject<boolean> = new BehaviorSubject(false);
  static authenticatedBehaviourSubject: BehaviorSubject<boolean> = new BehaviorSubject(false);
  static authSuccessBehaviourSubject: BehaviorSubject<boolean> = new BehaviorSubject(false);
  static authErrorBehaviourSubject: BehaviorSubject<any> = new BehaviorSubject({});
  static tokenExpiredBehaviourSubject: BehaviorSubject<boolean> = new BehaviorSubject(false);
  static refreshTokenExpiredBehaviourSubject: BehaviorSubject<boolean> = new BehaviorSubject(false);

  // Keycloak state observables
  static initializedObs: Observable<boolean> = Keycloak.initializedBehaviourSubject.asObservable();
  static initializingObs: Observable<boolean> = Keycloak.initializingBehaviourSubject.asObservable();
  static authenticatedObs: Observable<boolean> = Keycloak.authenticatedBehaviourSubject.asObservable();
  static authSuccessObs: Observable<boolean> = Keycloak.authSuccessBehaviourSubject.asObservable();
  static authErrorObs: Observable<boolean> = Keycloak.authErrorBehaviourSubject.asObservable();
  static tokenExpiredObs: Observable<boolean> = Keycloak.tokenExpiredBehaviourSubject.asObservable();
  static refreshTokenExpiredObs: Observable<boolean> = Keycloak.refreshTokenExpiredBehaviourSubject.asObservable();

  private lock: Lock = Lock.getInstance();

  // internal objects
  public config: any;
  public adapter: any; // = {};
  public resourceAccess: any; // = {};
  public callback_id: number; // = 0;
  public loginIframe: LoginIframe; // = new LoginIframe(true, [], 5);
  public callbackStorage: any; // = {};
  public timeSkew: number; // = 0;
  public loginRequired: boolean; // = false;

  // Token objects
  public tokenParsed: any; // = {};
  public idTokenParsed: any; // = {};
  public refreshTokenParsed: any; // = {};
  public accessToken: string; // = '';
  public idToken: string; // = '';
  public refreshToken: string; // = '';
  public tokenTimeoutHandle: any; // = {};
  public refreshTokenTimeoutHandle: any; // = {};
  public subject: string; // = '';
  public sessionId: string; // = '';

  // OIDC client properties
  public responseMode: string; // = '';
  public responseType: string; // = '';
  public flow: string; // = '';
  public clientId: string; // = '';
  public clientSecret: string; // = '';
  public authServerUrl: string; // = '';
  public realm: string; // = '';
  public realmAccess: any; // = {};

  public http: Http;

  // Keycloak methods
  public login(options: any) {
    return this.adapter.login(options);
  }

  public logout(options: any) {
    return this.adapter.logout(options);
  }

  public updateToken(minValidity: number): Observable<string> {
    return new Observable<string>((observer: any) => {
      minValidity = minValidity || 5;

      if (!this.isTokenExpired(minValidity)) {
        // console.info('token still valid');
        observer.next(this.accessToken);
      } else {
        if (this.isRefreshTokenExpired(5)) {
          this.login(this.config);
        } else {
          // console.info('refreshing token');
          const params: URLSearchParams = new URLSearchParams();
          params.set('grant_type', 'refresh_token');
          params.set('refresh_token', this.refreshToken);

          const url = this.getRealmUrl() + '/protocol/openid-connect/token';
          // console.info('getting url');
          const headers = new Headers({
            'Content-type': 'application/x-www-form-urlencoded'
          });

          if (this.clientId && this.clientSecret) {
            headers.append(
              'Authorization',
              'Basic ' + btoa(this.clientId + ': ' + this.clientSecret)
            );
          } else {
            params.set('client_id', this.clientId);
          }

          let timeLocal = new Date().getTime();

          const options: RequestOptionsArgs = {
            'headers': headers,
            'withCredentials': true
          };

          // console.info('calling url ' + url);
          this.http.post(url, params, options).subscribe((token: any) => {
            timeLocal = (timeLocal + new Date().getTime()) / 2;

            const tokenResponse = token.json();
            // console.info('parsed access token ' + tokenResponse['access_token']);
            this.setToken(
              tokenResponse['access_token'],
              tokenResponse['refresh_token'],
              tokenResponse['id_token'],
              true
            );

            this.timeSkew = Math.floor(timeLocal / 1000) - this.tokenParsed.iat;
            observer.next(tokenResponse['access_token']);
          });
        }
      }
    });
  }

  public register(options: any) {
    return this.adapter.register(options);
  }

  public accountManagement(options: any) {
    return this.adapter.accountManagement(options);
  }

  public loadUserProfile(): Observable<any> {
    const url = this.getRealmUrl() + '/account';
    const headers = new Headers({
      Accept: 'application/json',
      Authorization: 'bearer ' + this.accessToken
    });
    const options: RequestOptionsArgs = { 'headers': headers };
    return (this.http as Http).get(url, options).map(profile => profile.json());
  }

  public loadUserInfo(): Observable<any> {
    const url = this.getRealmUrl() + '/protocol/openid-connect/userinfo';
    const headers = new Headers({
      'Accept': 'application/json',
      'Authorization': 'bearer ' + this.accessToken
    });

    const options: RequestOptionsArgs = { 'headers': headers };
    return (this.http as Http).get(url, options).map(profile => profile.json());
  }

  public hasRealmRole(role: string): boolean {
    const access = this.realmAccess;
    return !!access && access.roles.indexOf(role) >= 0;
  }

  public hasResourceRole(role: string, resource: string): boolean {
    if (!this.resourceAccess) {
      return false;
    }

    const access: any = this.resourceAccess[resource || this.clientId];
    return !!access && access.roles.indexOf(role) >= 0;
  }

  public isTokenExpired(minValidity: number): boolean {
    if (!this.tokenParsed || (!this.refreshToken && this.flow !== 'implicit')) {
      throw new Error('Not authenticated');
    }

    let expiresIn =
      this.tokenParsed['exp'] - new Date().getTime() / 1000 + this.timeSkew;
    if (minValidity) {
      expiresIn -= minValidity;
    }

    return expiresIn < 0;
  }

  public isRefreshTokenExpired(minValidity: number): boolean {
    if (!this.tokenParsed || (!this.refreshToken && this.flow !== 'implicit')) {
      throw new Error('Not authenticated');
    }

    let expiresIn =
      this.refreshTokenParsed['exp'] -
      new Date().getTime() / 1000 +
      this.timeSkew;
    if (minValidity) {
      expiresIn -= minValidity;
    }

    return expiresIn < 0;
  }

  public clearToken(initOptions: any) {
    if (this.accessToken) {
      this.setToken('', '', '', true);
      Keycloak.authenticatedBehaviourSubject.next(false);

      if (this.loginRequired) {
        this.login(initOptions);
      }
    }
  }

  // URLs methods
  public createLoginUrl(options: any): string {
    const state = UUID.UUID();
    const nonce = UUID.UUID();

    let redirectUri = this.adapter.redirectUri(options);
    if (options && options.prompt) {
      redirectUri +=
        (redirectUri.indexOf('?') === -1 ? '?' : '&') +
        'prompt=' +
        options.prompt;
    }

    this.callbackStorage.add({
      'state': state,
      'nonce': nonce,
      'redirectUri': redirectUri
    });

    let action = 'auth';
    if (options && options.action === 'register') {
      action = 'registrations';
    }

    const scope =
      options && options.scope ? 'openid ' + options.scope : 'openid';

    let url =
      this.getRealmUrl() +
      '/protocol/openid-connect/' +
      action +
      '?client_id=' +
      encodeURIComponent(this.clientId) +
      '&redirect_uri=' +
      encodeURIComponent(redirectUri) +
      '&state=' +
      encodeURIComponent(state) +
      '&nonce=' +
      encodeURIComponent(nonce) +
      '&response_mode=' +
      encodeURIComponent(this.responseMode) +
      '&response_type=' +
      encodeURIComponent(this.responseType) +
      '&scope=' +
      encodeURIComponent(scope);

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

    return url;
  }

  public createLogoutUrl(options: any): string {
    const url =
      this.getRealmUrl() +
      '/protocol/openid-connect/logout' +
      '?redirect_uri=' +
      encodeURIComponent(this.adapter.redirectUri(options, false));

    return url;
  }

  public createRegisterUrl(options: any): string {
    if (!options) {
      options = {};
    }
    options.action = 'register';
    return this.createLoginUrl(options);
  }

  public createAccountUrl(options: any): string {
    const url =
      this.getRealmUrl() +
      '/account' +
      '?referrer=' +
      encodeURIComponent(this.clientId) +
      '&referrer_uri=' +
      encodeURIComponent(this.adapter.redirectUri(options));

    return url;
  }

  public getRealmUrl(): string {
    if (this.authServerUrl.charAt(this.authServerUrl.length - 1) === '/') {
      return this.authServerUrl + 'realms/' + encodeURIComponent(this.realm);
    } else {
      return this.authServerUrl + '/realms/' + encodeURIComponent(this.realm);
    }
  }

  public checkLoginIframe(): Observable<boolean> {
    return new Observable<boolean>((observer: any) => {
      if (this.loginIframe.iframe && this.loginIframe.iframeOrigin) {
        const msg = this.clientId + ' ' + this.sessionId;
        const origin = this.loginIframe.iframeOrigin;

        // console.info("KC_CORE: sending message to iframe "+msg+" origin :"+origin);
        this.loginIframe.iframe.contentWindow.postMessage(msg, origin);
        observer.next(true);
      } else {
        // promise.setSuccess();
        observer.next(true);
      }
    });
  }

  public processCallback(oauth: any) {
    const code = oauth.code;
    const error = oauth.error;
    const prompt = oauth.prompt;
    let timeLocal = new Date().getTime();

    if (error) {
      if (prompt !== 'none') {
        const errorData = {
          'error': error,
          'error_description': oauth.error_description
        };
        Keycloak.authErrorBehaviourSubject.next(errorData);
      }
      return;
    } else if (
      this.flow !== 'standard' &&
      (oauth.access_token || oauth.id_token)
    ) {
      authSuccess(oauth.access_token, '', oauth.id_token, true, this);
    }

    if (this.flow !== 'implicit' && code) {
      const url = this.getRealmUrl() + '/protocol/openid-connect/token';
      const params: URLSearchParams = new URLSearchParams();
      params.set('code', code);
      params.set('grant_type', 'authorization_code');

      const headers = new Headers({
        'Content-type': 'application/x-www-form-urlencoded'
      });

      if (this.clientId && this.clientSecret) {
        headers.append(
          'Authorization',
          'Basic ' + btoa(this.clientId + ':' + this.clientSecret)
        );
      } else {
        params.set('client_id', this.clientId);
      }
      params.set('redirect_uri', oauth.redirectUri);
      const options: RequestOptionsArgs = {
        'headers': headers,
        'withCredentials': false
      };

      (this.http as Http).post(url, params, options).subscribe(token => {
        const tokenResponse = token.json();
        authSuccess(
          tokenResponse['access_token'],
          tokenResponse['refresh_token'],
          tokenResponse['id_token'],
          this.flow === 'standard',
          this
        );
      });
    }

    function authSuccess(
      accessToken: string,
      refreshToken: string,
      idToken: string,
      fulfillPromise: any,
      kc: any
    ) {
      timeLocal = (timeLocal + new Date().getTime()) / 2;

      kc.setToken(accessToken, refreshToken, idToken, true);

      if (
        (kc.tokenParsed && kc.tokenParsed.nonce !== oauth.storedNonce) ||
        (kc.refreshTokenParsed &&
          kc.refreshTokenParsed.nonce !== oauth.storedNonce) ||
        (kc.idTokenParsed && kc.idTokenParsed.nonce !== oauth.storedNonce)
      ) {
        // console.log('invalid nonce!');
        kc.clearToken({});
      } else {
        kc.timeSkew = Math.floor(timeLocal / 1000) - kc.tokenParsed.iat;

        if (fulfillPromise) {
          Keycloak.authSuccessBehaviourSubject.next(true);
        }
      }
    }
  }

  public setToken(
    accessToken: string,
    refreshToken: string,
    idToken: string,
    useTokenTime: boolean
  ) {
    if (this.tokenTimeoutHandle) {
      clearTimeout(this.tokenTimeoutHandle);
      this.tokenTimeoutHandle = null;
    }

    if (this.refreshTokenTimeoutHandle) {
      clearTimeout(this.refreshTokenTimeoutHandle);
      this.refreshTokenTimeoutHandle = null;
    }

    if (accessToken) {
      this.accessToken = accessToken;
      this.tokenParsed = new Token().decodeToken(accessToken);

      this.sessionId = this.tokenParsed.session_state;
      Keycloak.authenticatedBehaviourSubject.next(true);
      this.subject = this.tokenParsed.sub;
      this.realmAccess = this.tokenParsed.realm_access;
      this.resourceAccess = this.tokenParsed.resource_access;

      const start = useTokenTime
        ? this.tokenParsed.iat
        : new Date().getTime() / 1000;
      const expiresIn = this.tokenParsed.exp - start;
      this.tokenTimeoutHandle = setTimeout(
        this.pushTokenExpired,
        expiresIn * 1000
      );
    } else {
      delete this.accessToken;
      delete this.tokenParsed;
      delete this.subject;
      delete this.realmAccess;
      delete this.resourceAccess;
    }

    if (refreshToken) {
      this.refreshToken = refreshToken;
      this.refreshTokenParsed = new Token().decodeToken(refreshToken);

      const start = useTokenTime
        ? this.refreshTokenParsed.iat
        : new Date().getTime() / 1000;
      const expiresIn = this.refreshTokenParsed.exp - start;
      this.refreshTokenTimeoutHandle = setTimeout(
        this.pushTokenExpired,
        expiresIn * 1000
      );
    } else {
      delete this.refreshToken;
      delete this.refreshTokenParsed;
    }

    if (idToken) {
      this.idToken = idToken;
      this.idTokenParsed = new Token().decodeToken(idToken);
    } else {
      delete this.idToken;
      delete this.idTokenParsed;
    }
  }

  public pushTokenExpired() {
    Keycloak.tokenExpiredBehaviourSubject.next(true);
  }

  public createCallbackId(): string {
    const id = '<id: ' + this.callback_id++ + Math.random() + '>';
    return id;
  }

  public parseCallback(url: string): any {
    const oauth: any = URIParser.parseUri(url, this.responseMode);
    const state: string = oauth.state;
    const oauthState = this.callbackStorage.get(state);

    if (
      oauthState &&
      (oauth.code || oauth.error || oauth.access_token || oauth.id_token)
    ) {
      oauth.redirectUri = oauthState.redirectUri;
      oauth.storedNonce = oauthState.nonce;

      if (oauth.fragment) {
        oauth.newUrl += '#' + oauth.fragment;
      }

      return oauth;
    }
  }

  // public constructor
  constructor(@Inject(PLATFORM_ID) private platformId: any) {
    this.loginIframe = new LoginIframe(true, [], 5);
  }

  public init(initOptions: any) {
    // console.info('KC_CORE: init called...');
    if (
      isPlatformBrowser(this.platformId) &&
      !Keycloak.initializedBehaviourSubject.getValue() &&
      !this.lock.isAquired()
    ) {
      this.lock.acquire();

      // console.info('KC_CORE: initializing...');

      try {
        this.callbackStorage = new LocalStorage();
      } catch (err) {
        this.callbackStorage = new CookieStorage();
      }

      if (initOptions && initOptions.adapter === 'cordova') {
        this.adapter = this.loadAdapter('cordova');
      } else if (initOptions && initOptions.adapter === 'default') {
        this.adapter = this.loadAdapter('default');
      } else {
        if (window && (window as any)['cordova']) {
          this.adapter = this.loadAdapter('cordova');
        } else {
          this.adapter = this.loadAdapter('default');
        }
      }

      // options processing
      if (initOptions) {
        if (typeof initOptions.checkLoginIframe !== 'undefined') {
          this.loginIframe.enable = initOptions.checkLoginIframe;
        }

        if (initOptions.checkLoginIframeInterval) {
          this.loginIframe.interval = initOptions.checkLoginIframeInterval;
        }

        if (initOptions.onLoad === 'login-required') {
          this.loginRequired = true;
        }

        if (initOptions.responseMode) {
          if (
            initOptions.responseMode === 'query' ||
            initOptions.responseMode === 'fragment'
          ) {
            this.responseMode = initOptions.responseMode;
          } else {
            throw new Error('Invalid value for responseMode');
          }
        }

        if (initOptions.flow) {
          switch (initOptions.flow) {
            case 'standard':
              this.responseType = 'code';
              break;
            case 'implicit':
              this.responseType = 'id_token token';
              break;
            case 'hybrid':
              this.responseType = 'code id_token token';
              break;
            default:
              throw new Error('Invalid value for flow');
          }
          this.flow = initOptions.flow;
        }
      }

      if (!this.responseMode) {
        this.responseMode = 'fragment';
      }
      if (!this.responseType) {
        this.responseType = 'code';
        this.flow = 'standard';
      }

      // loading this conf

      this.loadConfig(this.config).subscribe(loaded => {
        if (loaded) {
          Keycloak.initializedBehaviourSubject.next(true);
          this.processInit(initOptions, this).subscribe(initialized => {
            // console.info("KC_CORE : notifying initialized");
            // this.initializingBehaviourSubject.next(false);
          });
        }
      });
    }
  }

  private loadConfig(configuration: any): Observable<boolean> {
    return new Observable<boolean>((observer: any) => {
      let configUrl: string = '';
      if (!configuration) {
        configUrl = 'keycloak.json';
      } else if (typeof configuration === 'string') {
        configUrl = configuration;
      }

      if (configUrl !== '') {
        (this.http as Http)
          .get(configUrl)
          .map(res => res.json())
          .subscribe(config => {
            this.authServerUrl = config['auth-server-url'];
            this.realm = config['realm'];
            this.clientId = config['resource'];
            this.clientSecret = (config['credentials'] || {})['secret'];

            observer.next(true);
            // console.info("Keycloak initialized !");
          });
      } else {

        if (!configuration['realm']) {
          throw new Error('realm missing');
        }

        if (!configuration['resource']) {
          throw new Error('clientId missing');
        }

        if (!configuration['auth-server-url']) {
          throw new Error('auth server url missing');
        }

        this.authServerUrl = configuration['auth-server-url'];
        this.realm = configuration['realm'];
        this.clientId = configuration['resource'];
        this.clientSecret = (configuration.credentials || {}).secret;
        observer.next(true);
      }
    });
  }

  private processInit(initOptions: any, kc: any): Observable<boolean> {
    return new Observable<boolean>((observer: any) => {
      if (window) {
        const callback = this.parseCallback(window.location.href);
        // let initPromise:any = Keycloak.createPromise;

        if (callback) {
          this.setupCheckLoginIframe(kc).subscribe(setup => {
            // console.info("KC_CORE: replacing window url");
            window.history.replaceState({}, null, callback.newUrl);
            this.processCallback(callback);
          });
        } else if (initOptions) {
          if (initOptions.token || initOptions.refreshToken) {
            this.setToken(
              initOptions.token,
              initOptions.refreshToken,
              initOptions.idToken,
              false
            );
            this.timeSkew = initOptions.timeSkew || 0;

            if (this.loginIframe.enable) {
              this.setupCheckLoginIframe(kc).subscribe(setup => {
                this.checkLoginIframe().subscribe((checked: boolean) => {
                  observer.next(true);
                });
              });
            } else {
              observer.next(true);
            }
          } else if (initOptions.onLoad) {
            const options: any = {};
            const doLogin = function doLoginCall(prompt: any) {
              if (!prompt) {
                options.prompt = 'none';
              }
              kc.login(options);
            };

            switch (initOptions.onLoad) {
              case 'check-sso':
                // console.info('login iframe ? '+Keycloak.loginIframe.enable);
                if (this.loginIframe.enable) {
                  this.setupCheckLoginIframe(kc).subscribe(setup => {
                    this.checkLoginIframe().subscribe(checked => {
                      doLogin(false);
                    });
                  });
                } else {
                  doLogin(false);
                }
                break;
              case 'login-required':
                doLogin(true);
                break;
              default:
                throw new Error('Invalid value for onLoad');
            }
          } else {
            observer.next(true);
          }
        } else {
          observer.next(true);
        }
      }
    });
  }

  private setupCheckLoginIframe(kc: any): Observable<boolean> {
    return new Observable<boolean>((observer: any) => {
      // console.info('Configuring login iframe...');
      if (!this.loginIframe.enable) {
        // console.info('login iframe IS NOT enabled');
        observer.next(true);
        return;
      }

      if (this.loginIframe.iframe) {
        // console.info('login iframe enabled and already created');
        observer.next(true);
        return;
      }

      const iframe: any = document.createElement('iframe');
      this.loginIframe.iframe = iframe;

      const check = function execCheck() {
        // Keycloak.checkLoginIframe().subscribe(check => {
        // console.info('iframe checked');
        // });
        if (kc.accessToken) {
          setTimeout(check, kc.loginIframe.interval * 1000);
        }
      };

      iframe.keycloak = kc;
      iframe.onload = function iframeOnLoad() {
        const realmUrl = this.keycloak.getRealmUrl();
        if (realmUrl.charAt(0) === '/') {
          // const origin: any;
          if (window && !window.location.origin) {
            this.keycloak.loginIframe.iframeOrigin =
              window.location.protocol +
              '//' +
              window.location.hostname +
              (window.location.port ? ': ' + window.location.port : '');
          } else {
            this.keycloak.loginIframe.iframeOrigin = window.location.origin;
          }
        } else {
          this.keycloak.loginIframe.iframeOrigin = realmUrl.substring(
            0,
            realmUrl.indexOf('/', 8)
          );
        }
        // console.info('login iframe LOADED');
        observer.next(true);

        setTimeout(check, this.keycloak.loginIframe.interval * 1000);
      };

      const src =
        this.getRealmUrl() +
        '/protocol/openid-connect/login-status-iframe.html';

      // console.info('configuring iframe url to ' + src);
      iframe.setAttribute('src', src);
      iframe.style.display = 'none';
      document.body.appendChild(iframe);

      const messageCallback = function getMessageCallback(event: any) {
        // console.info('checking iframe message callback..'+event.data+' '+event.origin);
        if (
          event.origin !== kc.loginIframe.iframeOrigin ||
          kc.loginIframe.iframe.contentWindow !== event.source
        ) {
          // console.info('event is not coming from the iframe, ignoring it');
          return;
        }
        if (
          !(
            event.data === 'unchanged' ||
            event.data === 'changed' ||
            event.data === 'error'
          )
        ) {
          // console.info('unknown event data, ignoring it');
          return;
        }

        if (event.data !== 'unchanged') {
          // console.info('event from the iframe, and data changed, clearing tokens');
          kc.clearToken({});
        }
      };
      window.addEventListener('message', messageCallback, false);
    });
  }

  private loadAdapter(type: string): any {
    if (!type || type === 'default') {
      return new DefaultAdapter(this);
    }
    if (type === 'cordova') {
      return new CordovaAdapter(this);
    }
    throw new Error('invalid adapter type: ' + type);
  }
}
