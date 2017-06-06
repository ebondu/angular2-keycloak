import { NgModule } from '@angular/core';
import { HttpModule, Http, XHRBackend, RequestOptions } from '@angular/http';

import { Keycloak } from './services/keycloak.core.service';
import { KeycloakAuthorization } from './services/keycloak.auth.service';
import { KeycloakHttp } from './services/keycloak.http.service';

export function keycloakHttpFactory(backend: XHRBackend, defaultOptions: RequestOptions, keycloakAuth: KeycloakAuthorization, keycloak: Keycloak) {
    return new KeycloakHttp(backend, defaultOptions, keycloak, keycloakAuth);
}

@NgModule({
    imports: [ HttpModule ],
    declarations: [ ],
    providers: [Keycloak, KeycloakAuthorization, KeycloakHttp,
        {provide: Http,
        useFactory: keycloakHttpFactory,
        deps: [XHRBackend, RequestOptions, Keycloak, KeycloakAuthorization]
        }],
    exports:  [ ]
})
export class Ng2KeycloakModule {}
