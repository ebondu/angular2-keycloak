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
import {
    Http,
    RequestMethod,
    Response,
    RequestOptionsArgs,
    RequestOptions,
    Headers,
    Request,
    ConnectionBackend
} from '@angular/http';

import { Observable, BehaviorSubject } from 'rxjs/Rx';
import 'rxjs/operator/map';
import 'rxjs/operator/filter';
import 'rxjs/operator/catch';
import { KeycloakAuthorization } from '../services/keycloak.auth.service';
import { Keycloak } from '../services/keycloak.core.service';

/**
 * An Angular http proxy supporting Keycloak auth & authz.
 * Authenticate user, manage tokens and add authorization header to access to remote Keycloak protected resources.
 */
@Injectable()
export class KeycloakHttp extends Http {

    // Observable on service status.
    // If true, keycloakHttp is ready to handle requests
    static readyBehaviourSubject: BehaviorSubject<boolean> = new BehaviorSubject(false);
    static readyObs: Observable<boolean> = KeycloakHttp.readyBehaviourSubject.asObservable();

    private MAX_UNAUTHORIZED_ATTEMPTS: number = 2;

    constructor(backend: ConnectionBackend,
                defaultOptions: RequestOptions,
                private keycloak: Keycloak,
                private keycloakAuth: KeycloakAuthorization) {

        super(backend, defaultOptions);
        Keycloak.http = new Http(backend, defaultOptions);
        //this.keycloak.init({});
        //this.keycloakAuth.init();
    }

    get(url: string, options ?: RequestOptionsArgs): Observable <Response> {
        // console.info("GET");
        options = options || {withCredentials: false};
        options.method = RequestMethod.Get;
        return this.configureRequest(url, 1, options);
    }

    post(url: string, body: string, options ?: RequestOptionsArgs): Observable <Response> {
        options = options || {withCredentials: false};
        options.method = RequestMethod.Post;
        options.body = body;
        return this.configureRequest(url, 1, options);
    }

    put(url: string, body: string, options ?: RequestOptionsArgs): Observable <Response> {
        options = options || {withCredentials: false};
        options.method = RequestMethod.Put;
        options.body = body;
        return this.configureRequest(url, 1, options);
    }

    delete(url: string, options ?: RequestOptionsArgs): Observable <Response> {
        options = options || {withCredentials: false};
        options.method = RequestMethod.Delete;
        return this.configureRequest(url, 1, options);
    }

    patch(url: string, body: string, options ?: RequestOptionsArgs): Observable <Response> {
        options = options || {withCredentials: false};
        options.method = RequestMethod.Patch;
        options.body = body;
        return this.configureRequest(url, 1, options);
    }

    head(url: string, options ?: RequestOptionsArgs): Observable <Response> {
        options = options || {withCredentials: false};
        options.method = RequestMethod.Head;
        return this.configureRequest(url, 1, options);
    }

    private configureRequest(url:string | Request, count: number, options?: RequestOptionsArgs): Observable<Response> {

        if (options.withCredentials && !KeycloakHttp.readyBehaviourSubject.getValue()) {
            KeycloakAuthorization.initializedObs.take(1).filter(init => init === true).subscribe(() => {
                console.info('KC_HTTP: keycloak authz initialized...');
            });

            Keycloak.initializedObs.take(1).filter(init => init === true).subscribe(() => {
                if (!Keycloak.authenticatedBehaviourSubject.getValue()) {
                    console.info('KC_HTTP: keycloak initialized, go login...');
                    Keycloak.login(true);
                }
            });

            Keycloak.authenticatedObs.take(2).filter(auth => auth === true).subscribe(() => {
                console.info('KC_HTTP: authentication done...');
                KeycloakHttp.readyBehaviourSubject.next(true);
            });

            return KeycloakHttp.readyObs.take(2).filter(ready => ready === true).flatMap(ready => {
                console.info('KC_HTTP: keycloak is now http ready, re-attempting request...');
                return this.configureRequest(url, count, options);
            });
        } else {

            // KC is ready, getting authorization header

            return this.setHeaders(options).flatMap(options => {

                console.info('KC_HTTP: using headers ' + options);
                // calling http with headers
                return super.request(url, options).catch(error => {

                    // error handling
                    let status = error.status;
                    if ((status === 403 || status === 401) && count < this.MAX_UNAUTHORIZED_ATTEMPTS) {
                        console.info('KC_HTTP: request is unauthorized!');
                        if (error.url.indexOf('/authorize') === -1) {
                            // auth error handling, observing for authorization
                            return new Observable((observer:any) => {

                                if (error.headers.get('WWW-Authenticate') !== null) {
                                    // requesting authorization to KC server
                                    KeycloakAuthorization.authorize(error.headers.get('WWW-Authenticate')).subscribe(token => {
                                        // notifying observers for authz result token
                                        observer.next(token);
                                    });
                                } else {
                                    console.warn('WWW-Authenticate header not found' + error.headers.get('WWW-Authenticate'));
                                }
                            });
                        }
                    } else {
                        Observable.throw('server error');
                    }
                });
            }).flatMap(res => {
                // Http Response or Authz token
                if (res instanceof Response) {

                    // Http response
                    return new Observable<Response>((observer:any) =>
                        observer.next(res)
                    );
                } else {

                    // Authorization token
                    Keycloak.accessToken = <any>res;
                    count = count + 1;
                    // retrying request with new token
                    console.info('KC_HTTP: retrying request with new authorization token');
                    return this.configureRequest(url, count, options);
                }
            });
        }
    }

    // to add 'Authorization' header
    private setHeaders(options: RequestOptionsArgs): Observable<RequestOptionsArgs> {
        return new Observable<RequestOptionsArgs>((observer: any) => {

            if (options.withCredentials) {
                console.info('adding headers with options ' + options);
                let token = Keycloak.accessToken;
                if (Keycloak.refreshToken) {
                    console.info('checking token');
                    Keycloak.updateToken(5).subscribe(res => {
                        token = res;
                        if (!options.headers) {
                            options.headers = new Headers();
                        }
                        console.info('returning an updated token');
                        options.headers.set('Authorization', 'Bearer ' + token);
                        observer.next(options);
                    });
                } else {
                    if (!options.headers) {
                        options.headers = new Headers();
                    }
                    console.info('returning the existing token ');
                    options.headers.set('Authorization', 'Bearer ' + token);
                    observer.next(options);
                }
            } else {
                observer.next(options);
            }
        });
    }
}
