import { Injectable } from '@angular/core';
import {
    Http,
    RequestMethod,
    Response,
    RequestOptionsArgs,
    Headers,
    Request
} from '@angular/http';

import { Observable, BehaviorSubject } from 'rxjs/Rx';
import 'rxjs/operator/map';
import 'rxjs/operator/filter';
import 'rxjs/operator/catch';

import { KeycloakAuthorization } from './keycloak.auth.service';
import { Keycloak } from './keycloak.core.service';

/**
 * A http proxy supporting keycloak auth / authz.
 */

@Injectable()
export class KeycloakHttp {

    // Observable on service status.
    // If true, keycloakHttp is ready to handle requests
    static readyBehaviourSubject: BehaviorSubject<boolean> = new BehaviorSubject(false);
    static readyObs: Observable<boolean> = KeycloakHttp.readyBehaviourSubject.asObservable();

    private MAX_UNAUTHORIZED_ATTEMPTS: number = 2;

    // constructor
    constructor(private http: Http, private keycloakAuth: KeycloakAuthorization, private keycloak: Keycloak) {
        this.keycloak.init({});
        this.keycloakAuth.init();
    }


    get(url: string, options ?: RequestOptionsArgs): Observable <Response> {
        // console.info("GET");
        options = options || {};
        options.method = RequestMethod.Get;
        return this.request(url, 1, options);
    }

    post(url: string, body: string, options ?: RequestOptionsArgs): Observable <Response> {
        options = options || {};
        options.method = RequestMethod.Post;
        options.body = body;
        return this.request(url, 1, options);
    }

    put(url: string, body: string, options ?: RequestOptionsArgs): Observable <Response> {
        options = options || {};
        options.method = RequestMethod.Put;
        options.body = body;
        return this.request(url, 1, options);
    }

    delete(url: string, options ?: RequestOptionsArgs): Observable <Response> {
        options = options || {};
        options.method = RequestMethod.Delete;
        return this.request(url, 1, options);
    }

    patch(url: string, body: string, options ?: RequestOptionsArgs): Observable <Response> {
        options = options || {};
        options.method = RequestMethod.Patch;
        options.body = body;
        return this.request(url, 1, options);
    }

    head(url: string, options ?: RequestOptionsArgs): Observable <Response> {
        options = options || {};
        options.method = RequestMethod.Head;
        return this.request(url, 1, options);
    }

    private request(url: string | Request, count: number, options?: RequestOptionsArgs): Observable<Response> {

        if (!KeycloakHttp.readyBehaviourSubject.getValue()) {

            KeycloakAuthorization.initializedObs.take(1).filter(init => init === true).subscribe(() => {
                console.log('keycloak authz initialized...');
            });

            Keycloak.initializedObs.take(1).filter(init => init === true).subscribe(() => {
                console.log('keycloak initialized...');
                Keycloak.login(true);
            });

            Keycloak.authenticatedObs.take(2).filter(auth => auth === true).subscribe(() => {
                console.log('keycloak authenticated...');
                KeycloakHttp.readyBehaviourSubject.next(true);
            });

            return KeycloakHttp.readyObs.take(2).filter(ready => ready === true).flatMap(ready => {
                console.log('keycloak http ready, re-attempting request...');
                return this.request(url, count, options);

            });
        } else {

            // KC is ready, getting authorization header

            return this.setHeaders(options).flatMap(options => {

                console.info('using headers ' + options);
                // calling http with headers
                return this.http.request(url, options).catch(error => {

                    // error handling
                    let status = error.status;
                    if ((status === 403 || status === 401) && count < this.MAX_UNAUTHORIZED_ATTEMPTS) {
                        console.warn('unauthorized!');
                        if (error.url.indexOf('/authorize') === -1) {
                            // auth error handling, observing for authorization
                            return new Observable((observer: any) => {

                                if (error.headers.get('WWW-Authenticate') !== null) {
                                    // requesting authorization to KC server
                                    this.keycloakAuth.authorize(error.headers.get('WWW-Authenticate')).subscribe(token => {
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
                    return new Observable<Response>((observer: any) =>
                        observer.next(res)
                    );
                } else {

                    // Authorization token
                    Keycloak.token = <any>res;
                    count = count + 1;
                    // retrying request with new token
                    console.log('retrying request with new authorization token');
                    return this.request(url, count, options);
                }
            });
        }
    }

    // to add 'Authorization' header
    private setHeaders(options: RequestOptionsArgs): Observable<RequestOptionsArgs> {
        return new Observable<RequestOptionsArgs>((observer: any) => {

            console.info('adding headers with options ' + options);
            let token = Keycloak.token;
            if (Keycloak.refreshToken) {
                console.info('checking token');
                Keycloak.updateToken(5).subscribe(res => {
                    token = res;
                    if (!options.headers) {
                        options.headers = new Headers();
                    }
                    console.info('updated token ' + token);
                    options.headers.set('Authorization', 'Bearer ' + token);
                    observer.next(options);
                });
            } else {
                if (!options.headers) {
                    options.headers = new Headers();
                }
                console.info('non updated token ' + token);
                options.headers.set('Authorization', 'Bearer ' + token);
                observer.next(options);
            }
        });
    }
}
