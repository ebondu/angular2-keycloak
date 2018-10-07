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


import { Injectable, Injector } from '@angular/core';
import { HttpErrorResponse, HttpEvent, HttpHandler, HttpInterceptor, HttpRequest } from '@angular/common/http';

import { Observable } from 'rxjs';
import { KeycloakService } from '../service/keycloak.service';
import { filter, first } from 'rxjs/operators';
import { UUID } from 'angular2-uuid';

@Injectable()
export class KeycloakInterceptor implements HttpInterceptor {

  private keycloak: KeycloakService;

  private id: UUID = UUID.UUID();

  constructor(private injector: Injector) {
    // console.log('Keycloak interceptor created :: ', this.id);
  }

  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {

    if (!this.keycloak) {
      this.keycloak = this.injector.get(KeycloakService);
      // console.log('Keycloak service :: ', this.keycloak);
    }

    if (req.withCredentials && !req.headers.has('Authorization')) {

      return new Observable<HttpEvent<any>>((observer: any) => {

        this.keycloak.initializedObs.pipe(filter(initialized => initialized)).subscribe(initialized => {
          this.keycloak.initializedAuthzdObs.pipe(filter(authzInit => authzInit)).subscribe(authzInit => {
            if (!this.keycloak.accessToken) {
              // console.log('Login required...');
              this.keycloak.login({});
            }
          });
        });
        this.keycloak.authenticationObs.pipe(first(auth => auth)).subscribe(initialized => {
          // console.log('Using authz service...');

          this.keycloak.updateToken(5).subscribe(token => {
            const authToken = 'Bearer ' + token;
            const authReq = req.clone({
              headers: req.headers
                .set('Authorization', authToken)
                .set('Accept', 'application/json')
            });

            // const authReq = req.clone();
            // send cloned request with header to the next handler.
            next.handle(authReq).subscribe(
              (event: HttpEvent<any>) => {
                observer.next(event);
              },
              (error: any) => {
                if (error instanceof HttpErrorResponse) {
                  if (error.status === 401) {
                    // console.log('Need UMA authorization');
                    if (error.headers.has('WWW-Authenticate')) {
                      // console.log('using www-authenticate hearder');

                      this.keycloak.authorize(error.headers.get('WWW-Authenticate')).subscribe(
                        (authorized: boolean) => {
                          // console.log('Using token from service after authz');
                          const authReqWithRpt = req.clone({
                            headers: req.headers
                              .set('Authorization', 'Bearer ' + this.keycloak.accessToken)
                              .set('Accept', 'application/json')
                          });
                          next.handle(authReqWithRpt).subscribe(event => {
                            observer.next(event);
                          }, errorEndpoint => {
                            observer.error(errorEndpoint);
                          });
                        },
                        (error_authz: any) => {
                          // console.log('Unable to authorize request', error_authz);
                          observer.error(error);
                        }
                      );
                    } else {
                      observer.error(error);
                    }
                  } else {
                    // console.log('Error while calling endpoint', error);
                    observer.error(error);
                  }
                } else {
                  observer.error(error);
                }
              });
          });
        });
      });
    } else {
      return next.handle(req);
    }
  }
}
