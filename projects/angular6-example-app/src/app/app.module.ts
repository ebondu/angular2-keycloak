import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';

import { AppComponent } from './app.component';

import { HTTP_INTERCEPTORS, HttpClientModule } from '@angular/common/http';
import { KEYCLOAK_CONF, KEYCLOAK_INIT_OPTIONS, keycloakInterceptor } from '@ebondu/angular-keycloak';
import { keycloakConfig, keycloakInitOption } from '../environments/environment';

@NgModule({
  declarations: [
    AppComponent
  ],
  imports: [
    BrowserModule,
    HttpClientModule,
  ],
  providers: [
    {
      provide: KEYCLOAK_INIT_OPTIONS,
      useValue: keycloakInitOption
    },
    {
      provide: KEYCLOAK_CONF,
      useValue: keycloakConfig
    },
    {
      provide: HTTP_INTERCEPTORS,
      useValue: keycloakInterceptor,
      multi: true,
    },
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
