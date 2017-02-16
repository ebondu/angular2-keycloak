import { NgModule } from '@angular/core';
import { HttpModule, ConnectionBackend } from '@angular/http';

import { Keycloak } from './services/keycloak.core.service';
import { KeycloakAuthorization } from './services/keycloak.auth.service';
import { KeycloakHttp } from './services/keycloak.http.service';

import { Http, XHRBackend,RequestOptions } from '@angular/http';


@NgModule({
    imports: [ HttpModule ],
    declarations: [ ],
    providers: [Keycloak, KeycloakAuthorization, KeycloakHttp,
        {provide: Http,
        useFactory:
            (
                backend: XHRBackend,
                defaultOptions: RequestOptions,
                keycloakAuth: KeycloakAuthorization,
                keycloak: Keycloak
            ) => new KeycloakHttp(backend, defaultOptions, keycloak,  keycloakAuth),
        deps: [XHRBackend, RequestOptions, Keycloak, KeycloakAuthorization]
        }],
    exports:  [ ]
})
export class Ng2KeycloakModule {}
