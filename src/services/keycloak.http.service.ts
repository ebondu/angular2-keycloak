import {Injectable} from '@angular/core';
import {
  Http,
  RequestMethod,
  Response,
  RequestOptionsArgs,
  Headers,
  Request
} from '@angular/http';

import {Observable, BehaviorSubject} from 'rxjs/Rx';
import 'rxjs/operator/map';
import 'rxjs/operator/filter';
import 'rxjs/operator/catch';

import {KeycloakAuthorization} from './keycloak.auth.service';
import {Keycloak} from './keycloak.core.service';

/**
 * A http proxy supporting keycloak auth / authz.
 */

@Injectable()
export class KeycloakHttp {

  // Observable on service status.
  // If true, keycloakHttp is ready to handle requests
  static readyBehaviourSubject:BehaviorSubject<boolean> = new BehaviorSubject(false);
  static readyObs:Observable<boolean> = KeycloakHttp.readyBehaviourSubject.asObservable();

  // constructor
  constructor(private http:Http, private keycloakAuth:KeycloakAuthorization, private keycloak:Keycloak) {
    this.keycloakAuth.init();
  }


  get(url:string, options ?:RequestOptionsArgs):Observable < Response > {
    console.info("GET");
    options = options || {};
    options.method = RequestMethod.Get;
    return this.request(url, 0, options);
  }

  post(url:string, body:string, options ?:RequestOptionsArgs):Observable < Response > {
    options = options || {};
    options.method = RequestMethod.Post;
    options.body = body;
    return this.request(url, 0, options);
  }

  put(url:string, body:string, options ?:RequestOptionsArgs):Observable < Response > {
    options = options || {};
    options.method = RequestMethod.Put;
    options.body = body;
    return this.request(url, 0, options);
  }

  delete(url:string, options ?:RequestOptionsArgs):Observable < Response > {
    options = options || {};
    options.method = RequestMethod.Delete;
    return this.request(url, 0, options);
  }

  patch(url:string, body:string, options ?:RequestOptionsArgs):Observable < Response > {
    options = options || {};
    options.method = RequestMethod.Patch;
    options.body = body;
    return this.request(url, 0, options);
  }

  head(url:string, options ?:RequestOptionsArgs):Observable < Response > {
    options = options || {};
    options.method = RequestMethod.Head;
    return this.request(url, 0, options);
  }

  private request(url:string | Request, count:number, options?:RequestOptionsArgs):Observable<Response> {

    if (!KeycloakHttp.readyBehaviourSubject.getValue()) {

      KeycloakAuthorization.initializedObs.filter(init => init === true).subscribe(()=> {
        console.log("keycloak authz initialized...");
      })

      Keycloak.initializedObs.filter(init => init === true).subscribe(()=> {
        console.log("keycloak initialized...");
        Keycloak.login(true);
      })

      Keycloak.authenticatedObs.filter(auth => auth === true).subscribe(()=> {
        console.log("keycloak authenticated...");
        KeycloakHttp.readyBehaviourSubject.next(true);
      })

      return KeycloakHttp.readyObs.take(2).filter(ready => ready == true).flatMap(ready => {
        console.log("keycloak http ready, re-attempting request...");

        return this.request(url, count, options);

      });
    } else {

      // KC is ready, getting authorization header
      this.setHeaders(options);

      // calling http with headers
      return this.http.request(url, options).catch(error => {

        // error handling
        let status = error.status;
        if (status === 403 || status === 401) {
          if (error.url.indexOf('/authorize') === -1) {
            // auth error handling, observing for authorization
            return new Observable((observer:any) => {

              if (error.headers.get('WWW-Authenticate') != null) {
                // requesting authorization to KC server
                this.keycloakAuth.authorize(error.headers.get('WWW-Authenticate')).subscribe(token => {
                  // notifying observers for authz result token
                  observer.next(token);
                });
              } else {
                console.warn('WWW-Authenticate header not found');
              }
            });
          }
        } else {
          Observable.throw("server error");
        }
      }).flatMap(res => {
        // Http Response or Authz token
        if (res instanceof Response) {

          // Http response
          return new Observable<Response>((observer:any) =>
            observer.next(res)
          );
        } else {

          // Authorization token
          Keycloak.token = <any>res;

          // retrying request with new token
          return this.request(url, count, options);
        }
      });

    }
  }

  // to add 'Authorization' header
  private setHeaders(options:RequestOptionsArgs) {
    let token = Keycloak.token;
    if (!options.headers) {
      options.headers = new Headers();

    }
    options.headers.set('Authorization', 'Bearer ' + token);
  }
}
