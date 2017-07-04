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

import { Injectable } from '@angular/core';
import { Http, Headers, RequestOptionsArgs, URLSearchParams } from '@angular/http';
import { DefaultAdapter } from '../adapters/keycloak.adapter.default';
import { Observable, BehaviorSubject } from 'rxjs/Rx';
import 'rxjs/operator/map';
import { CordovaAdapter } from '../adapters/keycloak.adapter.cordova';
import { LocalStorage } from '../storage/keycloak.storage.local';
import { CookieStorage } from '../storage/keycloak.storage.cookie';
import { URIParser } from '../utils/keycloak.utils.URIParser';
import { LoginIframe } from '../utils/keycloak.utils.loginIframe';
import { UUID } from '../utils/keycloak.utils.UUID';
import { Token } from '../utils/keycloak.utils.token';
import { Lock } from '../utils/keycloak.utils.singleton';

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

    static lock: Lock = Lock.getInstance();
    
    // internal objects
    static config:any;
    static adapter:any;
    static resourceAccess:any;
    static callback_id:number = 0;
    static loginIframe:LoginIframe;
    static callbackStorage:any;
    static timeSkew:number;
    static http:Http;
    static loginRequired:boolean;


    // Token objects
    static tokenParsed:any;
    static idTokenParsed:any;
    static refreshTokenParsed:any;
    static accessToken:string;
    static idToken:string;
    static refreshToken:string;
    static tokenTimeoutHandle:any;
    static subject:string;
    static sessionId:string;


    // OIDC client properties
    static responseMode:string;
    static responseType:string;
    static flow:string;
    static clientId:string;
    static clientSecret:string;
    static authServerUrl:string;
    static realm:string;
    static realmAccess:any;

    // Keycloak state subjects
    static initializedBehaviourSubject:BehaviorSubject<boolean> = new BehaviorSubject(false);
    static initializingBehaviourSubject:BehaviorSubject<boolean> = new BehaviorSubject(false);
    static authenticatedBehaviourSubject:BehaviorSubject<boolean> = new BehaviorSubject(false);
    static authSuccessBehaviourSubject:BehaviorSubject<boolean> = new BehaviorSubject(false);
    static authErrorBehaviourSubject:BehaviorSubject<any> = new BehaviorSubject({});
    static tokenExpiredBehaviourSubject:BehaviorSubject<boolean> = new BehaviorSubject(false);

    // Keycloak state observables
    static initializedObs:Observable<boolean> = Keycloak.initializedBehaviourSubject.asObservable();
    static initializingObs:Observable<boolean> = Keycloak.initializingBehaviourSubject.asObservable();
    static authenticatedObs:Observable<boolean> = Keycloak.authenticatedBehaviourSubject.asObservable();
    static authSuccessObs:Observable<boolean> = Keycloak.authSuccessBehaviourSubject.asObservable();
    static authErrorObs:Observable<boolean> = Keycloak.authErrorBehaviourSubject.asObservable();
    static tokenExpiredObs:Observable<boolean> = Keycloak.tokenExpiredBehaviourSubject.asObservable();

    // Keycloak methods
    static login(options:any) {
        return Keycloak.adapter.login(options);
    }

    static logout(options:any) {
        return Keycloak.adapter.logout(options);
    }

    static updateToken(minValidity:number):Observable<string> {

        return new Observable<string>((observer:any) => {

            minValidity = minValidity || 5;

            if (!Keycloak.isTokenExpired(minValidity)) {
                console.info('token still valid');
                observer.next(Keycloak.accessToken);
            } else {
                if (Keycloak.isRefreshTokenExpired(5)) {
                    Keycloak.login(Keycloak.config);
                } else {
                    console.info('refreshing token');
                    let params:URLSearchParams = new URLSearchParams();
                    params.set('grant_type', 'refresh_token');
                    params.set('refresh_token', Keycloak.refreshToken);

                    let url = Keycloak.getRealmUrl() + '/protocol/openid-connect/token';
                    console.info('getting url');
                    let headers = new Headers({'Content-type': 'application/x-www-form-urlencoded'});

                    if (Keycloak.clientId && Keycloak.clientSecret) {
                        headers.append('Authorization', 'Basic ' + btoa(Keycloak.clientId + ': ' + Keycloak.clientSecret));
                    } else {
                        params.set('client_id', this.clientId);
                    }

                    let timeLocal = new Date().getTime();

                    let options:RequestOptionsArgs = {headers: headers, withCredentials: true};
                    console.info('calling url ' + url);
                    this.http.post(url, params, options).subscribe((token:any) => {
                        timeLocal = (timeLocal + new Date().getTime()) / 2;

                        let tokenResponse = token.json();
                        console.info('parsed access token ' + tokenResponse['access_token']);
                        Keycloak.setToken(tokenResponse['access_token'], tokenResponse['refresh_token'], tokenResponse['id_token'], true);

                        Keycloak.timeSkew = Math.floor(timeLocal / 1000) - Keycloak.tokenParsed.iat;
                        observer.next(tokenResponse['access_token']);
                    });
                }
            }
        });
    }

    static register(options:any) {
        return Keycloak.adapter.register(options);
    }

    static accountManagement(options:any) {
        return Keycloak.adapter.accountManagement(options);
    }

    static loadUserProfile():Observable<any> {
        let url = Keycloak.getRealmUrl() + '/account';
        let headers = new Headers({'Accept': 'application/json', 'Authorization': 'bearer ' + Keycloak.accessToken});

        let options:RequestOptionsArgs = {headers: headers};
        return Keycloak.http.get(url, options).map(profile => profile.json());
    }

    static loadUserInfo():Observable<any> {
        let url = Keycloak.getRealmUrl() + '/protocol/openid-connect/userinfo';
        let headers = new Headers({'Accept': 'application/json', 'Authorization': 'bearer ' + Keycloak.accessToken});

        let options:RequestOptionsArgs = {headers: headers};
        return Keycloak.http.get(url, options).map(profile => profile);
    }

    static hasRealmRole(role:string):boolean {
        let access = Keycloak.realmAccess;
        return !!access && access.roles.indexOf(role) >= 0;
    }

    static hasResourceRole(role:string, resource:string):boolean {
        if (!Keycloak.resourceAccess) {
            return false;
        }

        let access:any = Keycloak.resourceAccess[resource || Keycloak.clientId];
        return !!access && access.roles.indexOf(role) >= 0;
    }

    static isTokenExpired(minValidity:number):boolean {
        if (!Keycloak.tokenParsed || (!Keycloak.refreshToken && Keycloak.flow !== 'implicit' )) {
            throw 'Not authenticated';
        }

        let expiresIn = Keycloak.tokenParsed['exp'] - (new Date().getTime() / 1000) + Keycloak.timeSkew;
        if (minValidity) {
            expiresIn -= minValidity;
        }

        return expiresIn < 0;
    }

    static isRefreshTokenExpired(minValidity:number):boolean {
        if (!Keycloak.tokenParsed || (!Keycloak.refreshToken && Keycloak.flow !== 'implicit' )) {
            throw 'Not authenticated';
        }

        let expiresIn = Keycloak.refreshTokenParsed['exp'] - (new Date().getTime() / 1000) + Keycloak.timeSkew;
        if (minValidity) {
            expiresIn -= minValidity;
        }

        return expiresIn < 0;
    }

    static clearToken(initOptions:any) {
        if (Keycloak.accessToken) {
            Keycloak.setToken(null, null, null, true);
            Keycloak.authenticatedBehaviourSubject.next(false);

            if (Keycloak.loginRequired) {
                Keycloak.login(initOptions);
            }
        }
    }


    // URLs methods
    static createLoginUrl(options:any):string {
        let state = UUID.createUUID();
        let nonce = UUID.createUUID();

        let redirectUri = Keycloak.adapter.redirectUri(options);
        if (options && options.prompt) {
            redirectUri += (redirectUri.indexOf('?') === -1 ? '?': '&') + 'prompt=' + options.prompt;
        }

        Keycloak.callbackStorage.add({state: state, nonce: nonce, redirectUri: redirectUri});

        let action = 'auth';
        if (options && options.action === 'register') {
            action = 'registrations';
        }

        let scope = (options && options.scope) ? 'openid ' + options.scope: 'openid';

        let url = Keycloak.getRealmUrl()
            + '/protocol/openid-connect/' + action
            + '?client_id=' + encodeURIComponent(Keycloak.clientId)
            + '&redirect_uri=' + encodeURIComponent(redirectUri)
            + '&state=' + encodeURIComponent(state)
            + '&nonce=' + encodeURIComponent(nonce)
            + '&response_mode=' + encodeURIComponent(Keycloak.responseMode)
            + '&response_type=' + encodeURIComponent(Keycloak.responseType)
            + '&scope=' + encodeURIComponent(scope);

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

    static createLogoutUrl(options:any):string {
        let url = Keycloak.getRealmUrl()
            + '/protocol/openid-connect/logout'
            + '?redirect_uri=' + encodeURIComponent(Keycloak.adapter.redirectUri(options, false));

        return url;
    }

    static createRegisterUrl(options:any):string {
        if (!options) {
            options = {};
        }
        options.action = 'register';
        return Keycloak.createLoginUrl(options);
    }

    static createAccountUrl(options:any):string {
        let url = Keycloak.getRealmUrl()
            + '/account'
            + '?referrer=' + encodeURIComponent(Keycloak.clientId)
            + '&referrer_uri=' + encodeURIComponent(Keycloak.adapter.redirectUri(options));

        return url;
    }

    static getRealmUrl():string {
        if (Keycloak.authServerUrl.charAt(Keycloak.authServerUrl.length - 1) === '/') {
            return Keycloak.authServerUrl + 'realms/' + encodeURIComponent(Keycloak.realm);
        } else {
            return Keycloak.authServerUrl + '/realms/' + encodeURIComponent(Keycloak.realm);
        }
    }

    static checkLoginIframe(): Observable<boolean> {
        return new Observable<boolean>((observer: any) => {
            if (Keycloak.loginIframe.iframe && Keycloak.loginIframe.iframeOrigin) {

                let msg = Keycloak.clientId + ' ' + Keycloak.sessionId;
                let origin = Keycloak.loginIframe.iframeOrigin;

                console.info("KC_CORE: sending message to iframe "+msg+" origin :"+origin);
                Keycloak.loginIframe.iframe.contentWindow.postMessage(msg, origin);
                observer.next(true);
            } else {
                // promise.setSuccess();
                observer.next(true);
            }
        });
    }

    static processCallback(oauth:any) {
        let code = oauth.code;
        let error = oauth.error;
        let prompt = oauth.prompt;
        let timeLocal = new Date().getTime();

        if (error) {
            if (prompt !== 'none') {
                let errorData = {error: error, error_description: oauth.error_description};
                Keycloak.authErrorBehaviourSubject.next(errorData);
            }
            return;
        } else if ((Keycloak.flow !== 'standard') && (oauth.access_token || oauth.id_token)) {
            authSuccess(oauth.access_token, null, oauth.id_token, true);
        }

        if ((Keycloak.flow !== 'implicit') && code) {

            let url = Keycloak.getRealmUrl() + '/protocol/openid-connect/token';
            let params:URLSearchParams = new URLSearchParams();
            params.set('code', code);
            params.set('grant_type', 'authorization_code');

            let headers = new Headers({'Content-type': 'application/x-www-form-urlencoded'});

            if (Keycloak.clientId && Keycloak.clientSecret) {
                headers.append('Authorization', 'Basic ' + btoa(Keycloak.clientId + ':' + Keycloak.clientSecret));
            } else {
                params.set('client_id', Keycloak.clientId);
            }
            params.set('redirect_uri', oauth.redirectUri);
            let options:RequestOptionsArgs = {headers: headers, withCredentials: true};

            this.http.post(url, params, options).subscribe(token => {
                let tokenResponse = token.json();
                authSuccess(
                    tokenResponse['access_token'],
                    tokenResponse['refresh_token'],
                    tokenResponse['id_token'],
                    Keycloak.flow === 'standard');
            });
        }

        function authSuccess(accessToken:string, refreshToken:string, idToken:string, fulfillPromise:any) {
            timeLocal = (timeLocal + new Date().getTime()) / 2;

            Keycloak.setToken(accessToken, refreshToken, idToken, true);

            if ((Keycloak.tokenParsed && Keycloak.tokenParsed.nonce !== oauth.storedNonce) ||
                (Keycloak.refreshTokenParsed && Keycloak.refreshTokenParsed.nonce !== oauth.storedNonce) ||
                (Keycloak.idTokenParsed && Keycloak.idTokenParsed.nonce !== oauth.storedNonce)) {

                console.log('invalid nonce!');
                Keycloak.clearToken({});

            } else {
                Keycloak.timeSkew = Math.floor(timeLocal / 1000) - Keycloak.tokenParsed.iat;

                if (fulfillPromise) {
                    Keycloak.authSuccessBehaviourSubject.next(true);
                }
            }
        }
    }


    static setToken(accessToken:string, refreshToken:string, idToken:string, useTokenTime:boolean) {
        if (Keycloak.tokenTimeoutHandle) {
            clearTimeout(Keycloak.tokenTimeoutHandle);
            Keycloak.tokenTimeoutHandle = null;
        }

        if (accessToken) {
            Keycloak.accessToken = accessToken;
            Keycloak.tokenParsed = Token.decodeToken(accessToken);

            Keycloak.sessionId = Keycloak.tokenParsed.session_state;
            Keycloak.authenticatedBehaviourSubject.next(true);
            Keycloak.subject = Keycloak.tokenParsed.sub;
            Keycloak.realmAccess = Keycloak.tokenParsed.realm_access;
            Keycloak.resourceAccess = Keycloak.tokenParsed.resource_access;


            let start = useTokenTime ? Keycloak.tokenParsed.iat: (new Date().getTime() / 1000);
            let expiresIn = Keycloak.tokenParsed.exp - start;
            Keycloak.tokenTimeoutHandle = setTimeout(Keycloak.tokenExpiredBehaviourSubject.next(true), expiresIn * 1000);
        } else {
            delete Keycloak.accessToken;
            delete Keycloak.tokenParsed;
            delete Keycloak.subject;
            delete Keycloak.realmAccess;
            delete Keycloak.resourceAccess;
        }

        if (refreshToken) {
            Keycloak.refreshToken = refreshToken;
            Keycloak.refreshTokenParsed = Token.decodeToken(refreshToken);
        } else {
            delete Keycloak.refreshToken;
            delete Keycloak.refreshTokenParsed;
        }

        if (idToken) {
            Keycloak.idToken = idToken;
            Keycloak.idTokenParsed = Token.decodeToken(idToken);
        } else {
            delete Keycloak.idToken;
            delete Keycloak.idTokenParsed;
        }
    }


    static createCallbackId():string {
        let id = '<id: ' + (Keycloak.callback_id++) + (Math.random()) + '>';
        return id;
    }

    static parseCallback(url:string):any {
        let oauth:any = URIParser.parseUri(url, Keycloak.responseMode);
        let state:string = oauth.state;
        let oauthState = Keycloak.callbackStorage.get(state);

        if (oauthState && (oauth.code || oauth.error || oauth.access_token || oauth.id_token)) {
            oauth.redirectUri = oauthState.redirectUri;
            oauth.storedNonce = oauthState.nonce;

            if (oauth.fragment) {
                oauth.newUrl += '#' + oauth.fragment;
            }

            return oauth;
        }
    }

    // public constructor
    constructor() {
        Keycloak.loginIframe = new LoginIframe(true, [], 5);
    }

    public init(initOptions:any) {
        
        console.info('KC_CORE: init called...');
        if (!Keycloak.initializedBehaviourSubject.getValue() && !Keycloak.lock.isAquired()) {
            Keycloak.lock.acquire();

            console.info('KC_CORE: initializing...');

            try {
                Keycloak.callbackStorage = new LocalStorage();
            } catch (err) {
                Keycloak.callbackStorage = new CookieStorage();
            }

            if (initOptions && initOptions.adapter === 'cordova') {
                Keycloak.adapter = this.loadAdapter('cordova');
            } else if (initOptions && initOptions.adapter === 'default') {
                Keycloak.adapter = this.loadAdapter('default');
            } else {
                if (window[<any>'cordova']) {
                    Keycloak.adapter = this.loadAdapter('cordova');
                } else {
                    Keycloak.adapter = this.loadAdapter('default');
                }
            }

            // options processing
            if (initOptions) {
                if (typeof initOptions.checkLoginIframe !== 'undefined') {
                    Keycloak.loginIframe.enable = initOptions.checkLoginIframe;
                }

                if (initOptions.checkLoginIframeInterval) {
                    Keycloak.loginIframe.interval = initOptions.checkLoginIframeInterval;
                }

                if (initOptions.onLoad === 'login-required') {
                    Keycloak.loginRequired = true;
                }

                if (initOptions.responseMode) {
                    if (initOptions.responseMode === 'query' || initOptions.responseMode === 'fragment') {
                        Keycloak.responseMode = initOptions.responseMode;
                    } else {
                        throw 'Invalid value for responseMode';
                    }
                }

                if (initOptions.flow) {
                    switch (initOptions.flow) {
                        case 'standard':
                            Keycloak.responseType = 'code';
                            break;
                        case 'implicit':
                            Keycloak.responseType = 'id_token token';
                            break;
                        case 'hybrid':
                            Keycloak.responseType = 'code id_token token';
                            break;
                        default:
                            throw 'Invalid value for flow';
                    }
                    Keycloak.flow = initOptions.flow;
                }
            }

            if (!Keycloak.responseMode) {
                Keycloak.responseMode = 'fragment';
            }
            if (!Keycloak.responseType) {
                Keycloak.responseType = 'code';
                Keycloak.flow = 'standard';
            }

            // loading keycloak conf

            this.loadConfig(Keycloak.config).subscribe(loaded => {
                if (loaded) {
                    Keycloak.initializedBehaviourSubject.next(true);
                    this.processInit(initOptions).subscribe(initialized => {
                        console.info("KC_CORE : notifying initialized");

                        //Keycloak.initializingBehaviourSubject.next(false);
                    });
                }
            });
        }
    }

    private loadConfig(url:string):Observable<boolean> {
        return new Observable<boolean>((observer:any) => {
            let configUrl:string;
            if (!Keycloak.config) {
                configUrl = 'keycloak.json';
            } else if (typeof Keycloak.config === 'string') {
                configUrl = Keycloak.config;
            }

            if (configUrl) {

                Keycloak.http.get(configUrl).map(res => res.json()).subscribe(config => {

                    Keycloak.authServerUrl = config['auth-server-url'];
                    Keycloak.realm = config['realm'];
                    Keycloak.clientId = config['resource'];
                    Keycloak.clientSecret = (config['credentials'] || {})['secret'];

                    observer.next(true);
                    // console.info("Keycloak initialized !");
                });
            } else {
                if (!Keycloak.config['url']) {
                    let scripts = document.getElementsByTagName('script');
                    for (let i = 0; i < scripts.length; i++) {
                        if (scripts[i].src.match(/.*keycloak\.js/)) {
                            Keycloak.config.url = scripts[i].src.substr(0, scripts[i].src.indexOf('/js/keycloak.js'));
                            break;
                        }
                    }
                }

                if (!Keycloak.config.realm) {
                    throw 'realm missing';
                }

                if (!Keycloak.config.clientId) {
                    throw 'clientId missing';
                }

                Keycloak.authServerUrl = Keycloak.config.url;
                Keycloak.realm = Keycloak.config.realm;
                Keycloak.clientId = Keycloak.config.clientId;
                Keycloak.clientSecret = (Keycloak.config.credentials || {}).secret;
                observer.next(true);
            }
        });
    }


    private processInit(initOptions:any):Observable<boolean> {
        return new Observable<boolean>((observer:any) => {

            let callback = Keycloak.parseCallback(window.location.href);
            // let initPromise:any = Keycloak.createPromise;

            if (callback) {
                this.setupCheckLoginIframe().subscribe(setup => {
                        window.history.replaceState({}, null, callback.newUrl);
                        Keycloak.processCallback(callback);
                    }
                );

            } else if (initOptions) {
                if (initOptions.token || initOptions.refreshToken) {
                    Keycloak.setToken(initOptions.token, initOptions.refreshToken, initOptions.idToken, false);
                    Keycloak.timeSkew = initOptions.timeSkew || 0;

                    if (Keycloak.loginIframe.enable) {
                        this.setupCheckLoginIframe().subscribe(setup => {
                            Keycloak.checkLoginIframe().subscribe((checked: boolean) => {
                                observer.next(true);
                            });
                        });
                    } else {
                        observer.next(true);
                    }
                } else if (initOptions.onLoad) {

                    let options:any = {};
                    let doLogin = function (prompt:any) {
                        if (!prompt) {
                            options.prompt = 'none';
                        }
                        Keycloak.login(options);
                    };

                    switch (initOptions.onLoad) {
                        case 'check-sso':

                            console.info('login iframe ? '+Keycloak.loginIframe.enable);
                            if (Keycloak.loginIframe.enable) {
                                this.setupCheckLoginIframe().subscribe(setup => {
                                    Keycloak.checkLoginIframe().subscribe(checked => {
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
                            throw 'Invalid value for onLoad';
                    }
                } else {
                    observer.next(true);
                }
            } else {
                observer.next(true);
            }
        });
    }

    private setupCheckLoginIframe(): Observable<Boolean> {
        return new Observable<boolean>((observer: any) => {
            console.info('Configuring login iframe...');
            if (!Keycloak.loginIframe.enable) {
                console.info('login iframe IS NOT enabled');
                observer.next(true);
                return;
            }

            if (Keycloak.loginIframe.iframe) {
                console.info('login iframe enabled and already created');
                observer.next(true);
                return;
            }

            let iframe:any = document.createElement('iframe');
            Keycloak.loginIframe.iframe = iframe;

            let check = function () {
                Keycloak.checkLoginIframe().subscribe(check => {
                    console.info('iframe checked');
                });
                if (Keycloak.accessToken) {
                    setTimeout(check, Keycloak.loginIframe.interval * 1000);
                }
            };

            iframe.onload = function () {
                let realmUrl = Keycloak.getRealmUrl();
                if (realmUrl.charAt(0) === '/') {
                    let origin: any;
                    if (!window.location.origin) {
                        Keycloak.loginIframe.iframeOrigin = window.location.protocol
                            + '//' + window.location.hostname
                            + (window.location.port ? ': ' + window.location.port: '');
                    } else {
                        Keycloak.loginIframe.iframeOrigin = window.location.origin;
                    }
                } else {
                    Keycloak.loginIframe.iframeOrigin = realmUrl.substring(0, realmUrl.indexOf('/', 8));
                }
                console.info('login iframe LOADED');
                observer.next(true);

                setTimeout(check, Keycloak.loginIframe.interval * 1000);
            };

            let src = Keycloak.getRealmUrl() + '/protocol/openid-connect/login-status-iframe.html';

            console.info('configuring iframe url to ' + src);
            iframe.setAttribute('src', src);
            iframe.style.display = 'none';
            document.body.appendChild(iframe);

            let messageCallback = function (event:any) {
                console.info('checking iframe message callback..'+event.data+' '+event.origin);
                if ((event.origin !== Keycloak.loginIframe.iframeOrigin) || (Keycloak.loginIframe.iframe.contentWindow !== event.source)) {
                    console.info('event is not coming from the iframe, ignoring it');
                    return;
                }
                if (!(event.data == 'unchanged' || event.data == 'changed' || event.data == 'error')) {
                    console.info('unknown event data, ignoring it');
                    return;
                }

                if (event.data !== 'unchanged') {
                    console.info('event from the iframe, and data changed, clearing tokens');
                    Keycloak.clearToken({});
                }
            };
            window.addEventListener('message', messageCallback, false);
        });
    }

    private loadAdapter(type:string):any {
        if (!type || type === 'default') {
            return new DefaultAdapter();
        }
        if (type === 'cordova') {
            return new CordovaAdapter();
        }
        throw 'invalid adapter type: ' + type;
    }
}
