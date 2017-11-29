import { Component, OnInit } from '@angular/core';
import { Keycloak, KeycloakAuthorization } from "@ebondu/angular2-keycloak";
import { Http } from "@angular/http";

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent implements OnInit {
  title = 'app';
  public parsedToken: any;
  public isAuthenticated: boolean;
  public profile: any;

  constructor(private keycloak: Keycloak, private keycloakAuthz: KeycloakAuthorization, private http: Http) {
    Keycloak.authenticatedObs.subscribe(auth => {
      this.isAuthenticated = auth;
      this.parsedToken = this.keycloak.tokenParsed;

      console.info('APP: authentication status changed...');
    });
  }

  ngOnInit() {
    // Configure the Keycloak
    console.log('Initializing AppComponent<--');
    this.keycloak.config = 'assets/keycloak.json';

    // Initialise the Keycloak
    this.keycloakAuthz.init();

    this.keycloak.init({
      checkLoginIframe: false
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
