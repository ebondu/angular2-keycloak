import {Injectable} from '@angular/core';
import {Http, Headers, RequestOptionsArgs} from '@angular/http';

import {Observable, BehaviorSubject} from 'rxjs/Rx';
import {Keycloak} from './keycloak.core.service';
import 'rxjs/operator/map';

/**
 * Keycloak Authorization manager
 */
@Injectable()
export class KeycloakAuthorization {

  static config: any;
  static initializedBehaviourSubject: BehaviorSubject<boolean> = new BehaviorSubject(false);
  static initializedObs: Observable<boolean> = KeycloakAuthorization.initializedBehaviourSubject.asObservable();

  private rpt: string;

  // constructor
  constructor(private http: Http, private keycloak: Keycloak) {

  }

  public init() {
    if (!KeycloakAuthorization.initializedBehaviourSubject.getValue()) {
      this.keycloak.loadConfig('keycloak.json').subscribe(status => {

        let url = Keycloak.authServerUrl + '/realms/' + Keycloak.realm + '/.well-known/uma-configuration';
        let headers = new Headers({'Accept': 'application/json'});
        let options: RequestOptionsArgs = {headers: headers};

        this.http.get(url, options).subscribe(authz => {
          KeycloakAuthorization.config = authz.json();

          // notifying initialization
          KeycloakAuthorization.initializedBehaviourSubject.next(true);
        });
      });
    }
  };

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
      let params = wwwAuthenticateHeader.split(',');
      let headers: any;
      let body: any;
      for (let i = 0; i < params.length; i++) {
        let param = params[i].split('=');

        if (param[0] === 'ticket') {
          let ticket = param[1].substring(1, param[1].length - 1).trim();

          headers = new Headers({'Content-type': 'application/json'});
          headers.append('Authorization', 'Bearer ' + Keycloak.token);

          body = JSON.stringify(
            {
              ticket: ticket,
              rpt: this.rpt
            }
          );
        }
      }

      let options: RequestOptionsArgs = {headers: headers};

      return this.http.post(KeycloakAuthorization.config.rpt_endpoint, body, options).map(token => {

        let status = token.status;

        if (status >= 200 && status < 300) {

          // Token retrieved
          let rpt = JSON.parse(token.text()).rpt;
          this.rpt = rpt;
          return rpt;
        } else if (status === 403) {

          console.error('Authorization request was denied by the server.');
          Observable.throw('Authorization request was denied by the server.');
        } else {

          console.error('Could not obtain authorization data from server.');
          Observable.throw('Could not obtain authorization data from server.');
        }
      });

    } else if (wwwAuthenticateHeader.indexOf('KC_ETT') !== -1) {
      let params = wwwAuthenticateHeader.substring('KC_ETT'.length).trim().split(',');
      let clientId: string = null;

      for (let i = 0; i < params.length; i++) {
        let param = params[i].split('=');

        if (param[0] === 'realm') {
          clientId = param[1].substring(1, param[1].length - 1).trim();
        }
      }
      return this.entitlement(clientId);
    }
  }

  /**
   * Obtains all entitlements from a Keycloak Server based on a give resourceServerId.
   */
  public entitlement(resourceSeververId: string): Observable<any> {

    return new Observable<any>((observer: any) => {

      let url = Keycloak.authServerUrl + '/realms/' + Keycloak.realm + '/authz/entitlement/' + resourceSeververId;
      let headers = new Headers({'Authorization': 'Bearer ' + Keycloak.token});
      let options: RequestOptionsArgs = {headers: headers};

      this.http.get(url, options).map(token => {
        let status = token.status;

        if (status >= 200 && status < 300) {
          let rpt: any = JSON.parse(token.text()).rpt;
          this.rpt = rpt;

          observer.next(rpt);
        } else if (status === 403) {

          console.error('Authorization request was denied by the server.');
          Observable.throw('Authorization request was denied by the server.');
        } else {

          console.error('Could not obtain authorization data from server.');
          Observable.throw('Authorization request was denied by the server.');
        }
      });
    });
  };
}
