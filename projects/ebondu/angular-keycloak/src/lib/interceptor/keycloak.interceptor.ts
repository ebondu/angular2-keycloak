/*
 * Copyright 2026 ebondu and/or its affiliates
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
import { HttpErrorResponse, HttpEvent, HttpHandlerFn, HttpInterceptorFn, HttpRequest } from '@angular/common/http';

import { Observable, throwError } from 'rxjs';
import { KeycloakService } from '../service/keycloak.service';
import { catchError, filter, first, switchMap, tap } from 'rxjs/operators';

export const keycloakInterceptor: HttpInterceptorFn = (req: HttpRequest<unknown>, next: HttpHandlerFn): Observable<HttpEvent<unknown>> => {
  if (!req.withCredentials || req.headers.has('Authorization')) {
    return next(req);
  }
  const keycloak = inject(KeycloakService);
  return keycloak.initializedObs.pipe(
    filter(Boolean),
    first(),
    switchMap(() => keycloak.initializedAuthzObs.pipe(filter(Boolean), first())),
    tap(() => {
      if (!keycloak.accessToken) {
        keycloak.login({}); // Short-circuit the end of the stream by redirecting to the login page
      }
    }),
    switchMap(() => keycloak.updateToken(5).pipe(first())),
    switchMap((token) => {
      const authReq = req.clone({
        headers: req.headers
          .set('Authorization', `Bearer ${token}`)
          .set('Accept', 'application/json')
      });
      return next(authReq).pipe(
        catchError((error: unknown) => {
          if (
            error instanceof HttpErrorResponse &&
            error.status === 401 &&
            error.headers.has('WWW-Authenticate')
          ) {
            return keycloak.authorize(error.headers.get('WWW-Authenticate')!).pipe(
              filter(Boolean),
              first(),
              switchMap((authorizedToken) => {
                const rptReq = req.clone({
                  headers: req.headers
                    .set('Authorization', `Bearer ${authorizedToken}`)
                    .set('Accept', 'application/json')
                });
                return next(rptReq);
              }),
              catchError(() => throwError(() => error))
            );
          }
          return throwError(() => error);
        })
      );
    })
  );
};
