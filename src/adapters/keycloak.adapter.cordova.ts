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
import { Injectable } from '@angular/core';

declare var window: any;

/**
 * Cordova adapter for hybrid apps.
 */
@Injectable()
export class CordovaAdapter {
  public openBrowserTab(url: string, options: any) {
    const cordova = window.cordova;
    if (options.toolbarColor) {
      cordova.plugins.browsertab.themeable.openUrl(url, options);
    } else {
      cordova.plugins.browsertab.themeable.openUrl(url);
    }
  }

  public login(options: any) {
    // let promise = Keycloak.createPromise();
    let o = 'location=no';
    if (options && options.prompt === 'none') {
      o += ',hidden=yes';
    }
    const loginUrl = this.keycloak.createLoginUrl(options);

    // console.info('opening login frame from cordova: ' + loginUrl);
    if (!window.cordova) {
      throw new Error('Cannot authenticate via a web browser');
    }

    if (!window.cordova.InAppBrowser || !window.cordova.plugins.browsertab) {
      throw new Error(
        'The Apache Cordova InAppBrowser/BrowserTab plugins was not found and are required'
      );
    }

    let ref: any;
    // let ref = window.cordova.InAppBrowser.open(loginUrl, '_blank', o);
    // let ref = window.cordova.InAppBrowser.open(loginUrl, '_system', o);
    let completed = false;

    window.cordova.plugins.browsertab.themeable.isAvailable(
      function loginInTab(result: any, kc: any) {
        if (!result) {
          ref = window.cordova.InAppBrowser.open(loginUrl, '_system');
          ref.addEventListener('loadstart', function processLoadStartEvent(
            event: any
          ) {
            if (event.url.indexOf('http://localhost') === 0) {
              const callback = kc.keycloak.parseCallback(event.url);
              kc.keycloak.processCallback(callback);
              ref.close();
              completed = true;
            }
          });

          ref.addEventListener('loaderror', function processLoadErrorEvent(
            event: any
          ) {
            if (!completed) {
              if (event.url.indexOf('http://localhost') === 0) {
                const callback = kc.keycloak.parseCallback(event.url);
                kc.keycloak.processCallback(callback);
                ref.close();
                completed = true;
              } else {
                ref.close();
              }
            }
          });
        } else {
          kc.openBrowserTab(loginUrl, options);
        }
      },
      function notAvailableError(isAvailableError: any) {
        // console.info('failed to query availability of in-app browser tab');
      }
    );
  }

  public closeBrowserTab() {
    const cordova = window.cordova;
    cordova.plugins.browsertab.themeable.close();
    // completed = true;
  }

  public logout(options: any) {
    const cordova = window.cordova;
    const logoutUrl = this.keycloak.createLogoutUrl(options);
    let ref: any;
    let error: any;

    cordova.plugins.browsertab.themeable.isAvailable(
      function logoutInTab(result: any, kc: any) {
        if (!result) {
          ref = cordova.InAppBrowser.open(logoutUrl, '_system');
          ref.addEventListener(
            'loadstart',
            function processLogoutLoadStartEvent(event: any) {
              if (event.url.indexOf('http://localhost') === 0) {
                ref.close();
              }
            }
          );

          ref.addEventListener(
            'loaderror',
            function processLogoutLoadErrorEvent(event: any) {
              if (event.url.indexOf('http://localhost') === 0) {
                ref.close();
              } else {
                error = true;
                ref.close();
              }
            }
          );

          ref.addEventListener('exit', function processLogoutExitEvent(
            event: any
          ) {
            if (error) {
              // promise.setError();
            } else {
              kc.keycloak.clearToken({});
              // promise.setSuccess();
            }
          });
        } else {
          kc.openBrowserTab(logoutUrl, options);
        }
      },
      function logoutNotAvailable(isAvailableError: any) {
        // console.info('failed to query availability of in-app browser tab');
      }
    );
  }

  public register(options: any) {
    const registerUrl = this.keycloak.createRegisterUrl({});
    window.cordova.plugins.browsertab.themeable.isAvailable(
      function registerInTab(result: any, kc: any) {
        if (!result) {
          window.cordova.InAppBrowser.open(registerUrl, '_system');
        } else {
          kc.openBrowserTab(registerUrl, options);
        }
      },
      function registerTabNotAvailable(isAvailableError: any) {
        // console.info('failed to query availability of in-app browser tab');
      }
    );
  }

  public accountManagement(options: any) {
    const accountUrl = this.keycloak.createAccountUrl({});
    window.cordova.plugins.browsertab.themeable.isAvailable(
      function accountInTab(result: any, kc: any) {
        if (!result) {
          window.cordova.InAppBrowser.open(accountUrl, '_system');
        } else {
          kc.openBrowserTab(accountUrl, options);
        }
      },
      function accountInTabNotAvailable(isAvailableError: any) {
        // console.info('failed to query availability of in-app browser tab');
      }
    );
  }

  public redirectUri(options: any): any {
    if (options.redirectUri) {
      return options.redirectUri;
    } else {
      // should use deep link
      return 'http://localhost';
    }
  }

  constructor(private keycloak: Keycloak) {}
}
