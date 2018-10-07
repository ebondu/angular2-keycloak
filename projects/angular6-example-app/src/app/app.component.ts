import { Component } from '@angular/core';
import { KeycloakService } from '@ebondu/angular-keycloak';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent {
  title = 'angular6-example-app';

  public parsedToken: any;
  public isAuthenticated: boolean;
  public profile: any;

  constructor(private keycloak: KeycloakService) {
    this.keycloak.authenticationObs.subscribe(auth => {
      this.isAuthenticated = auth;
      this.parsedToken = this.keycloak.tokenParsed;
      console.log('APP: authentication status changed...');
    });
  }

  login() {
    // you should pass your login options
    this.keycloak.login({});
  }

  logout() {
    // you should pass your logout options
    this.keycloak.logout({});
  }

  loadProfile() {
    this.keycloak.loadUserProfile().subscribe(profile => {
      this.profile = profile;
    });
  }
}
