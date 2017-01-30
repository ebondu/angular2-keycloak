import { NgModule } from '@angular/core';

import { Keycloak } from './services/keycloak.core.service';
import { KeycloakAuthorization } from './services/keycloak.auth.service';
import { KeycloakHttp } from './services/keycloak.http.service';

@NgModule({
    imports: [ ],
    declarations: [ ],
    providers: [Keycloak, KeycloakAuthorization, KeycloakHttp],
    exports:  [ ]
})
export class Ng2KeycloakModule {}
