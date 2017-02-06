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

declare var window: any;

/**
 * Cordova adapter for hybrid apps.
 */
export class CordovaAdapter {

    public login(options: any) {
        //let promise = Keycloak.createPromise();
        let o = 'location=no';
        if (options && options.prompt === 'none') {
            o += ',hidden=yes';
        }
        let loginUrl = Keycloak.createLoginUrl(options);

        console.info('opening login frame from cordova: ' + loginUrl);
        if (!window.cordova) {
            throw new Error('Cannot authenticate via a web browser');
        }

        if (!window.cordova.InAppBrowser) {
            throw new Error('The Apache Cordova InAppBrowser plugin was not found and is required');
        }

        let ref = window.cordova.InAppBrowser.open(loginUrl, '_blank', o);
        let completed = false;

        ref.addEventListener('loadstart', function (event: any) {
            if (event.url.indexOf('http://localhost') === 0) {
                let callback = Keycloak.parseCallback(event.url);
                Keycloak.processCallback(callback);
                ref.close();
                completed = true;
            }
        });

        ref.addEventListener('loaderror', function (event: any) {
            if (!completed) {
                if (event.url.indexOf('http://localhost') === 0) {

                    let callback = Keycloak.parseCallback(event.url);
                    Keycloak.processCallback(callback);
                    ref.close();
                    completed = true;
                } else {
                    ref.close();
                }
            }
        });
    }

    public logout(options: any) {
        let logoutUrl = Keycloak.createLogoutUrl(options);
        let ref = window.cordova.InAppBrowser.open(logoutUrl, '_blank', 'location=no,hidden=yes');
        let error: any;

        ref.addEventListener('loadstart', function (event: any) {
            if (event.url.indexOf('http://localhost') === 0) {
                ref.close();
            }
        });

        ref.addEventListener('loaderror', function (event: any) {
            if (event.url.indexOf('http://localhost') === 0) {
                ref.close();
            } else {
                error = true;
                ref.close();
            }
        });

        ref.addEventListener('exit', function (event: any) {
            if (error) {
                //promise.setError();
            } else {
                Keycloak.clearToken({});
                //promise.setSuccess();
            }
        });
    }

    public register() {
        let registerUrl = Keycloak.createRegisterUrl({});
        let ref = window.cordova.InAppBrowser.open(registerUrl, '_blank', 'location=no');
        ref.addEventListener('loadstart', function (event: any) {
            if (event.url.indexOf('http://localhost') === 0) {
                ref.close();
            }
        });
    }

    public accountManagement() {
        let accountUrl = Keycloak.createAccountUrl({});
        let ref = window.cordova.InAppBrowser.open(accountUrl, '_blank', 'location=no');
        ref.addEventListener('loadstart', function (event: any) {
            if (event.url.indexOf('http://localhost') === 0) {
                ref.close();
            }
        });
    }

    public redirectUri(options: any): any {
        return 'http://localhost';
    }
}
