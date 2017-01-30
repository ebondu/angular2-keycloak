import { Keycloak } from '../services/keycloak.core.service';

declare var window: any;

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
        let ref = window.open(logoutUrl, '_blank', 'location=no,hidden=yes');
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
        let ref = window.open(registerUrl, '_blank', 'location=no');
        ref.addEventListener('loadstart', function (event: any) {
            if (event.url.indexOf('http://localhost') === 0) {
                ref.close();
            }
        });
    }

    public accountManagement() {
        let accountUrl = Keycloak.createAccountUrl({});
        let ref = window.open(accountUrl, '_blank', 'location=no');
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
