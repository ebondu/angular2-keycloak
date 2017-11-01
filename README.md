# angular2-keycloak

Native Typescript Keycloak library for angular2/4.

## Installation

To install this library, run:

```bash
$ npm install @ebondu/angular2-keycloak --save
```

## Development

To generate all `*.js`, `*.js.map` and `*.d.ts` files:

```bash
$ npm run build:dist
```

## Usage

Declare Keycloak module in angular app :

```javascript
import { KeycloakModule } from '@ebondu/angular2-keycloak';
...

@NgModule({
  declarations: [
    AppComponent
  ],
  imports: [
    HttpModule,
    KeycloakModule.forRoot()
  ],
  providers: [
    ...
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }


```

To login

```javascript
import { Keycloak, KeycloakAuthorization } from '@ebondu/angular2-keycloak';
...

export class MyLoginClass implements OnInit {

  public parsedToken: any;
  public isAuthenticated: boolean;
  public profile: any;

  constructor( private keycloak: Keycloak, private keycloakAuthz: KeycloakAuthorization) {
    Keycloak.authenticatedObs.subscribe(auth => {
      this.isAuthenticated = auth;
      this.parsedToken = this.keycloak.tokenParsed;

      console.info('APP: authentication status changed...');
    });
  }

  ngOnInit() {
    // Configure the Keycloak
    this.keycloak.config = 'assets/keycloak.json';

    // Initialise the Keycloak
    this.keycloakAuthz.init();
    
    this.keycloak.init({
      checkLoginIframe: false
    });
  }

  login() {
    // you should pass your login options
    Keycloak.login({});
  }

  logout() {
    // you should pass your logout options
    Keycloak.logout({});
  }

  loadProfile() {
    this.keycloak.loadUserProfile().subscribe(profile => {
      this.profile = profile;
    });
  }

  ...
}
```

Please, use Http interface to get access to Keycloak http proxy (authentication / authorization). 
Angular will inject the right provider class for you. Notes that init() methodes for Keycloak and KeycloakAuthz needs to be called first (i.e. in ngOnInit()).
To pass the Keycloak authorization header, use the 'withCredentials' option.

```javascript
import { Http } from '@angular/http';
...

@Injectable()
export class MyClass {
    // Angular will inject the instance of the KeycloakHttp class
    constructor(private http: Http) {}

    callAPI(): Observable<MyObject> {

      let headers = new Headers({'Accept' :'application/json'});
      let options: RequestOptionsArgs = { headers: headers, withCredentials: true  };
        return this.http.get("http://localhost/myAPI/myMethod",  options)
            .map(res => res.json())
            .catch(err => handleError(err));
     }
     ...
}
```

## Examples

* [`angular2-webpack-product-app`](https://github.com/ebondu/angular2-keycloak/blob/master/example/angular2-webpack-product-app)
* [`angular-cli-example-app`](https://github.com/ebondu/angular2-keycloak/blob/master/example/angular-cli-example-app)
## License

Apache2 © [ebondu](dev.ebondu@gmail.com)
# angular2-keycloak
