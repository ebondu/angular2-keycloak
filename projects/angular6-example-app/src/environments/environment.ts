// This file can be replaced during build by using the `fileReplacements` array.
// `ng build --prod` replaces `environment.ts` with `environment.prod.ts`.
// The list of file replacements can be found in `angular.json`.

import { KeycloakConfiguration, KeycloakFlow, KeycloakInitOptions, KeycloakOnLoad, KeycloakResponseMode } from '@ebondu/angular-keycloak';

export const environment = {
  production: false
};

export const keycloakInitOption: KeycloakInitOptions = {
  responseMode: KeycloakResponseMode.QUERY,
  flow: KeycloakFlow.STANDARD,
  // checkLoginIframe: true,
  // checkLoginIframeInterval: 10000,
  // onLoad: KeycloakOnLoad.LOGIN_REQUIRED
};

export const keycloakConfig: KeycloakConfiguration = {
  authServerUrl: 'http://localhost:8080/auth',
  realm: 'master',
  clientId: 'public-app'
};
