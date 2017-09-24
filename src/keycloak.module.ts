import { NgModule, ModuleWithProviders } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Http, XHRBackend, RequestOptions } from '@angular/http';

import { Keycloak } from './services/keycloak.core.service';
import { KeycloakAuthorization } from './services/keycloak.auth.service';
import { KeycloakHttp } from './services/keycloak.http.service';

export * from './adapters/keycloak.adapter.cordova';
export * from './adapters/keycloak.adapter.default';
export * from './services/keycloak.auth.service';
export * from './services/keycloak.core.service';
export * from './services/keycloak.http.service';
export * from './storage/keycloak.storage.cookie';
export * from './storage/keycloak.storage.local';
export * from './utils/keycloak.utils.loginIframe';
export * from './utils/keycloak.utils.singleton';
export * from './utils/keycloak.utils.token';
export * from './utils/keycloak.utils.URIParser';

export function keycloakHttpFactory(
  backend: XHRBackend,
  defaultOptions: RequestOptions,
  auth: KeycloakAuthorization,
  keycloak: Keycloak
): KeycloakHttp {
  return new KeycloakHttp(backend, defaultOptions, auth, keycloak);
}

@NgModule({
  imports: [CommonModule]
})
export class KeycloakModule {
  static forRoot(): ModuleWithProviders {
    return {
      ngModule: KeycloakModule,
      providers: [
        Keycloak,
        KeycloakAuthorization,
        KeycloakHttp,
        {
          provide: Http,
          useFactory: keycloakHttpFactory,
          deps: [XHRBackend, RequestOptions, KeycloakAuthorization, Keycloak]
        }
      ]
    };
  }
}
