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

import { Injectable, OnInit } from '@angular/core';
import { Http, Headers, RequestOptionsArgs } from '@angular/http';

import { Observable, BehaviorSubject } from 'rxjs/Rx';
import { Keycloak } from './keycloak.core.service';
import 'rxjs/operator/map';

/**
 * Keycloak Authorization manager.
 *
 * Manager authorization headers and tokens to access to protected resources.
 */
@Injectable()
export class KeycloakAuthorization {
  static initializedBehaviourSubject: BehaviorSubject<boolean> = new BehaviorSubject(false);
  static initializedObs: Observable<boolean> = KeycloakAuthorization.initializedBehaviourSubject.asObservable();

  public config: any;
  public rpt: string;

  /**
   * This method enables client applications to better integrate with resource servers protected by a Keycloak
   * policy enforcer.
   *
   * In this case, the resource server will respond with a 401 status code and a WWW-Authenticate header holding the
   * necessary information to ask a Keycloak server for authorization data using both UMA and Entitlement protocol,
   * depending on how the policy enforcer at the resource server was configured.
   */
  public authorize(wwwAuthenticateHeader: string): Observable<any> {
    if (wwwAuthenticateHeader.indexOf('UMA') !== -1) {
      const params: any = wwwAuthenticateHeader.split(',');
      let headers: any;
      let body: any;
      for (const param of params) {
        const paramValue: any = param.split('=');

        if (paramValue[0] === 'ticket') {
          const ticket = paramValue[1]
            .substring(1, paramValue[1].length - 1)
            .trim();

          headers = new Headers({ 'Content-type': 'application/json' });
          headers.append(
            'Authorization',
            'Bearer ' + this.keycloak.accessToken
          );

          body = JSON.stringify({
            'ticket': ticket,
            'rpt': this.rpt
          });
        }
      }

      const options: RequestOptionsArgs = { 'headers': headers };

      return (this.keycloak.http as Http)
        .post(this.config.rpt_endpoint, body, options)
        .map(token => {
          const status = token.status;

          if (status >= 200 && status < 300) {
            // Token retrieved
            const rpt = JSON.parse(token.text()).rpt;
            this.rpt = rpt;
            return rpt;
          } else if (status === 403) {
            // console.error('Authorization request was denied by the server.');
            Observable.throw('Authorization request was denied by the server.');
          } else {
            // console.error('Could not obtain authorization data from server.');
            Observable.throw(
              'Could not obtain authorization data from server.'
            );
          }
        });
    } else if (wwwAuthenticateHeader.indexOf('KC_ETT') !== -1) {
      const params: any = wwwAuthenticateHeader
        .substring('KC_ETT'.length)
        .trim()
        .split(',');
      let clientId: string = '';

      for (const param of params) {
        const paramValue: any = param.split('=');

        if (paramValue[0] === 'realm') {
          clientId = paramValue[1]
            .substring(1, paramValue[1].length - 1)
            .trim();
        }
      }
      return this.entitlement(clientId);
    }

    return Observable.throw('Unable to authorize');
  }

  /**
   * Obtains all entitlements from a this Server based on a give resourceServerId.
   */
  public entitlement(resourceSeververId: string): Observable<any> {
    return new Observable<any>((observer: any) => {
      const url =
        this.keycloak.authServerUrl +
        '/realms/' +
        this.keycloak.realm +
        '/authz/entitlement/' +
        resourceSeververId;
      const headers = new Headers({
        Authorization: 'Bearer ' + this.keycloak.accessToken
      });
      const options: RequestOptionsArgs = { 'headers': headers };

      (this.keycloak.http as Http).get(url, options).map(token => {
        const status = token.status;

        if (status >= 200 && status < 300) {
          const rpt: any = JSON.parse(token.text()).rpt;
          this.rpt = rpt;

          observer.next(rpt);
        } else if (status === 403) {
          // console.error('Authorization request was denied by the server.');
          Observable.throw('Authorization request was denied by the server.');
        } else {
          // console.error('Could not obtain authorization data from server.');
          Observable.throw('Authorization request was denied by the server.');
        }
      });
    });
  }

  // constructor
  constructor(private keycloak: Keycloak) {}

  public init() {
    // console.debug('KC_AUTHZ: this init authz...');
    if (!KeycloakAuthorization.initializedBehaviourSubject.getValue()) {
      Keycloak.initializedObs
        .filter((status: any) => status === true)
        .subscribe(status => {
          // console.debug('KC_AUTHZ: this initialized, loading authz...');
          const url =
            this.keycloak.authServerUrl +
            '/realms/' +
            this.keycloak.realm +
            '/.well-known/uma-configuration';
          const headers = new Headers({ 'Accept': 'application/json' });
          const options: RequestOptionsArgs = { 'headers': headers };

          (this.keycloak.http as Http).get(url, options).subscribe(authz => {
            this.config = authz.json();

            // notifying initialization
            KeycloakAuthorization.initializedBehaviourSubject.next(true);
          });
        });
    }
    // this.this.init({});
  }
}
