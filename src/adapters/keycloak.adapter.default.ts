import { Keycloak } from '../services/keycloak.core.service';

export class DefaultAdapter {

    public login(options: any) {
        window.location.href = Keycloak.createLoginUrl(options);
    }

    public logout(options: any) {
        window.location.href = Keycloak.createLogoutUrl(options);
    }

    public register(options: any) {
        window.location.href = Keycloak.createRegisterUrl(options);
    }

    public accountManagement() {
        window.location.href = Keycloak.createAccountUrl({});
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
                redirectUri += (redirectUri.indexOf('?') === -1 ? '?' : '&') + 'redirect_fragment=' +
                    encodeURIComponent(location.hash.substring(1));
            }
            return redirectUri;
        }
    }
}
