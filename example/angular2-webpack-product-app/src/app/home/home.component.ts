import { Response } from '@angular/http';
import { Component, OnInit } from '@angular/core';
import { Keycloak, KeycloakHttp } from '@ebondu/angular2-keycloak';
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
  private profile:any;
  constructor(private keycloak: Keycloak, private http: KeycloakHttp) {

    Keycloak.authenticatedObs.subscribe(auth => {
      this.isAuthenticated = auth;
      this.parsedToken = Keycloak.tokenParsed;

      console.info("APP: authentication status changed...");
    });
  }

  ngOnInit() {
    console.info("APP : initializing home component...");
    Keycloak.config = "angular2-product/keycloak.json";
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
    this.http.get('/database/products')
      .map((res:Response) => res.json())
      .subscribe(prods => this.products = prods,
        error => console.log(error));
  }
}
