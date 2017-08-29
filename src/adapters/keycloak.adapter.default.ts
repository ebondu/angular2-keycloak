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

import { Keycloak } from '../services/keycloak.core.service';
import { Injectable, OnInit } from '@angular/core';

/**
 * Default adapter for web browsers
 */
@Injectable()
export class DefaultAdapter {
  public login(options: any) {
    if (window) {
      window.location.href = this.keycloak.createLoginUrl(options);
    }
  }

  public logout(options: any) {
    if (window) {
      window.location.href = this.keycloak.createLogoutUrl(options);
    }
  }

  public register(options: any) {
    if (window) {
      window.location.href = this.keycloak.createRegisterUrl(options);
    }
  }

  public accountManagement() {
    if (window) {
      window.location.href = this.keycloak.createAccountUrl({});
    }
  }

  public redirectUri(options: any, encodeHash: boolean): string {
    if (arguments.length === 1) {
      encodeHash = true;
    }

    if (options && options.redirectUri) {
      return options.redirectUri;
    } else {
      let redirectUri = location.href;
      if (location.hash && encodeHash) {
        redirectUri = redirectUri.substring(0, location.href.indexOf('#'));
        redirectUri +=
          (redirectUri.indexOf('?') === -1 ? '?' : '&') +
          'redirect_fragment=' +
          encodeURIComponent(location.hash.substring(1));
      }
      return redirectUri;
    }
  }

  constructor(private keycloak: Keycloak) {}
}
