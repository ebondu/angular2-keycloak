import { NgModule, ModuleWithProviders } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpModule, Http, XHRBackend, RequestOptions } from '@angular/http';

import { Keycloak } from './services/keycloak.core.service';
import { KeycloakAuthorization } from './services/keycloak.auth.service';
import { KeycloakHttp } from './services/keycloak.http.service';

export * from './services/keycloak.core.service';
export * from './services/keycloak.http.service';
export * from './services/keycloak.auth.service';

export function keycloakHttpFactory(backend: XHRBackend, defaultOptions: RequestOptions, keycloakAuth: KeycloakAuthorization, keycloak: Keycloak) {
  return new KeycloakHttp(backend, defaultOptions, keycloak, keycloakAuth);
}

@NgModule({
  imports: [
    CommonModule,
    HttpModule
  ]
})
export class Ng2KeycloakModule {
  static forRoot(): ModuleWithProviders {
    return {
      ngModule: Ng2KeycloakModule,
      providers: [Keycloak, KeycloakAuthorization, KeycloakHttp,
        {provide: Http,
          useFactory: keycloakHttpFactory,
          deps: [XHRBackend, RequestOptions, Keycloak, KeycloakAuthorization]
        }],
    };
  }
}
