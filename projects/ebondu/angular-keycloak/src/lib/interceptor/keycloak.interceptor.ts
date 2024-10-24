/*
 * Copyright 2024 ebondu and/or its affiliates
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

import { inject } from '@angular/core';
import {
  HttpErrorResponse,
  HttpEvent,
  HttpEventType,
  HttpHandlerFn,
  HttpInterceptorFn,
  HttpRequest
} from '@angular/common/http';

import { Observable, throwError } from 'rxjs';
import { KeycloakService } from '../service/keycloak.service';
import { catchError, filter, finalize, first, switchMap, tap } from 'rxjs/operators';

export const keycloakInterceptor: HttpInterceptorFn = (req: HttpRequest<unknown>, next: HttpHandlerFn): Observable<HttpEvent<unknown>> => {
  if (req.withCredentials && !req.headers.has('Authorization')) {
    const keycloak = inject(KeycloakService);
    keycloak.initializedObs.pipe(filter(initialized => initialized)).subscribe(initialized => {
      keycloak.initializedAuthzObs.pipe(filter(authzInit => authzInit)).subscribe(authzInit => {
        if (!keycloak.accessToken) {
          // console.log('Login required...');
          keycloak.login({});
        }
      });
    });
    let lastResponseWithToken;
    let errorWithToken;
    let lastResponseWithRptToken;
    let errorWithRptToken;
    return keycloak.authenticationObs.pipe(
      first(auth => auth),
      switchMap(initialized =>
        // console.log('Using authz service...');
        keycloak.updateToken(5).pipe(
          switchMap(token => {
            const authToken = 'Bearer ' + token;
            const authReq = req.clone({
              headers: req.headers
                .set('Authorization', authToken)
                .set('Accept', 'application/json')
            });

            // const authReq = req.clone();
            // send cloned request with header to the next handler.
            // console.log('calling with auth token');
            return next(authReq).pipe(
              tap(response => {
                lastResponseWithToken = response;
                // console.log('success with token response', response);
              }),
              catchError((error: any) => {
                errorWithToken = error;
                if (error instanceof HttpErrorResponse) {
                  if (error.status === 401) {
                    // console.log('Need UMA authorization');
                    if (error.headers.has('WWW-Authenticate')) {
                      // console.log('using www-authenticate hearder');
                      return keycloak.authorize(error.headers.get('WWW-Authenticate'))
                        .pipe(
                          filter(authorizedToken => !!authorizedToken),
                          switchMap((authorizedToken: string) => {
                          // console.log('Using token from service after authz');
                          const authReqWithRpt = req.clone({
                            headers: req.headers
                              .set('Authorization', 'Bearer ' + authorizedToken)
                              .set('Accept', 'application/json')
                          });
                          return next(authReqWithRpt).pipe(
                            tap((response: HttpEvent<any>) => {
                              lastResponseWithRptToken = response;
                              if (response.type === HttpEventType.Response) {
                                // console.log('success with rpt response', response);
                              }
                            }),
                            catchError((err: any) => {
                              errorWithRptToken = err;
                              // console.log('error response', err);
                              return throwError(() => error);
                            }),
                            finalize(() => {
                              if (lastResponseWithRptToken.type === HttpEventType.Sent && !errorWithRptToken) {
                                // last response type was 0, and we haven't received an error
                                // console.log('aborted with rpt request');
                              }
                            })
                          );
                        }));
                    } else {
                      return throwError(() => error);
                    }
                  } else {
                    // console.log('Error while calling endpoint', error);
                    return throwError(() => error);
                  }
                } else {
                  return throwError(() => error);
                }
              }),
              finalize(() => {
                if (lastResponseWithToken.type === HttpEventType.Sent && !errorWithToken) {
                  // last response type was 0, and we haven't received an error
                  // console.log('aborted with token request');
                }
              }));
          }))
      )
    );
  } else {
    let lastResponse;
    let error;
    // console.log('calling without auth token');
    return next(req).pipe(
      tap((response: HttpEvent<any>) => {
        lastResponse = response;
        if (response.type === HttpEventType.Response) {
          // console.log('success response', response);
        }
      }),
      catchError((err: any) => {
        error = err;
        // console.log('error response', err);
        // TODO: error handling if required
        return throwError(() => error);
      }),
      finalize(() => {
        if (lastResponse.type === HttpEventType.Sent && !error) {
          // last response type was 0, and we haven't received an error
          // console.log('aborted request');
        }
      })
    );
  }
};
