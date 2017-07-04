import { Response, Http } from '@angular/http';
import { Component, OnInit } from '@angular/core';
import { Keycloak, KeycloakAuthorization } from '@ebondu/angular2-keycloak';
import 'rxjs/operator/map';
import 'rxjs/operator/filter';
import 'rxjs/operator/catch';

@Component({
  selector: 'my-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.scss']
})
export class HomeComponent implements OnInit {

  private parsedToken: any;
  private isAuthenticated: boolean;

  products: string[] = [];
  private profile: any;
  constructor(private keycloak: Keycloak, private keycloakAuthz: KeycloakAuthorization, private http: Http) {

    Keycloak.authenticatedObs.subscribe(auth => {
      this.isAuthenticated = auth;
      this.parsedToken = Keycloak.tokenParsed;

      console.info('APP: authentication status changed...');
    });
  }

  ngOnInit() {
    console.info('APP : initializing home component...');

    this.keycloakAuthz.init();

    // comment or change regarding your app-name
    Keycloak.config = 'angular2-product/keycloak.json';

    this.keycloak.init({
      checkLoginIframe: false
    });
  }

  login() {
    Keycloak.login({});
  }

  logout() {
    Keycloak.logout({});
  }

  loadProfile() {
    Keycloak.loadUserProfile().subscribe(profile => {
      this.profile = profile;
    });
  }

  reloadData() {

    // change regarding your backend address
    this.http.get('/database/products')
      .map((res: Response) => res.json())
      .subscribe(prods => this.products = prods,
        error => console.log(error));
  }
}
