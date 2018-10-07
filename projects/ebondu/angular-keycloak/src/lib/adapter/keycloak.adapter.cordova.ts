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

import { KeycloakService } from '../service/keycloak.service';

declare var window: any;

/**
 * Cordova adapter for hybrid apps.
 */
export class CordovaAdapter {

  constructor(private keycloak: KeycloakService) {

  }

  public login(options: any) {
    // let promise = Keycloak.createPromise();
    let o = 'location=no';
    if (options && options.prompt === 'none') {
      o += ',hidden=yes';
    }
    const loginUrl = this.keycloak.createLoginUrl(options);

    // console.log('opening login frame from cordova: ' + loginUrl);
    if (!window.cordova) {
      throw new Error('Cannot authenticate via a web browser');
    }

    if (!window.cordova.InAppBrowser || !window.cordova.plugins.browsertab) {
      throw new Error('The Apache Cordova InAppBrowser/BrowserTab plugins was not found and are required');
    }

    let ref: any;
    // let ref = window.cordova.InAppBrowser.open(loginUrl, '_blank', o);
    // let ref = window.cordova.InAppBrowser.open(loginUrl, '_system', o);
    let completed = false;

    window.cordova.plugins.browsertab.themeable.isAvailable(
      function (result: any) {
        if (!result) {
          ref = window.cordova.InAppBrowser.open(loginUrl, '_system');
          ref.addEventListener('loadstart', function (event: any) {
            if (event.url.indexOf('http://localhost') === 0) {
              const callback = this.keycloak.parseCallback(event.url);
              this.keycloak.processCallback(callback).subscribe(processed => {
                ref.close();
                completed = true;
              });
            }
          });

          ref.addEventListener('loaderror', function (event: any) {
            if (!completed) {
              if (event.url.indexOf('http://localhost') === 0) {

                const callback = this.keycloak.parseCallback(event.url);
                this.keycloak.processCallback(callback).subscribe(processed => {
                  this.closeBrowserTab();
                  // ref.close();
                  // completed = true;
                });
              } else {
                this.closeBrowserTab();
                // ref.close();
              }
            }
          });
        } else {
          this.openBrowserTab(loginUrl, options);
        }
      },
      function (isAvailableError: any) {
        console.error('failed to query availability of in-app browser tab');
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
      function (result: any) {
        if (!result) {
          ref = cordova.InAppBrowser.open(logoutUrl, '_system');
          ref.addEventListener('loadstart', function (event: any) {
            if (event.url.indexOf('http://localhost') === 0) {
              this.ref.close();
              this.closeBrowserTab();
            }
          });

          ref.addEventListener('loaderror', function (event: any) {
            if (event.url.indexOf('http://localhost') === 0) {
              this.ref.close();
              this.closeBrowserTab();
            } else {
              error = true;
              this.ref.close();
              this.closeBrowserTab();
            }
          });

          ref.addEventListener('exit', function (event: any) {
            if (error) {
              console.error('listener of in-app browser tab exited due to error', error);
            } else {
              this.keycloak.clearToken({});
            }
          });
        } else {
          this.openBrowserTab(logoutUrl, options);
        }
      },
      function (isAvailableError: any) {
        console.error('failed to query availability of in-app browser tab', isAvailableError);
      }
    );
  }

  public register(options: any) {
    const registerUrl = this.keycloak.createRegisterUrl({});
    window.cordova.plugins.browsertab.themeable.isAvailable(
      function (result: any) {
        if (!result) {
          window.cordova.InAppBrowser.open(registerUrl, '_system');
        } else {
          this.openBrowserTab(registerUrl, options);
        }
      },
      function (isAvailableError: any) {
        console.error('failed to query availability of in-app browser tab', isAvailableError);
      }
    );
  }

  public accountManagement(options: any) {
    const accountUrl = this.keycloak.createAccountUrl({});
    window.cordova.plugins.browsertab.themeable.isAvailable(
      function (result: any) {
        if (!result) {
          window.cordova.InAppBrowser.open(accountUrl, '_system');
        } else {
          this.openBrowserTab(accountUrl, options);
        }
      },
      function (isAvailableError: any) {
        console.error('failed to query availability of in-app browser tab', isAvailableError);
      }
    );
  }


  public passwordManagement(options: any) {
    const accountUrl = this.keycloak.createChangePasswordUrl({});
    window.cordova.plugins.browsertab.themeable.isAvailable(
      function (result: any) {
        if (!result) {
          window.cordova.InAppBrowser.open(accountUrl, '_system');
        } else {
          this.openBrowserTab(accountUrl, options);
        }
      },
      function (isAvailableError: any) {
        console.error('failed to query availability of in-app browser tab', isAvailableError);
      }
    );
  }

  public redirectUri(options: any): any {
    if (options.redirectUri) {
      return options.redirectUri;
    } else {
      return 'http://localhost';
    }
  }

  private openBrowserTab(url: String, options: any) {
    const cordova = window.cordova;
    if (options.toolbarColor) {
      cordova.plugins.browsertab.themeable.openUrl(url, options);
    } else {
      cordova.plugins.browsertab.themeable.openUrl(url);
    }
  }
}
