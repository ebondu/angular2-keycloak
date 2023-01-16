# angular-keycloak

Native Typescript Keycloak library for angular 12+.

Project generated by angular-cli as a library project 

This library is a native typescript implementation based on the official JS wrapper and provide :
* An angular `Service` to access to basic KC functions (login, logout, register, checkSSO on load, etc.)
* An angular `HttpInterceptor` to handle the token header injection / authorization workflow 
 


## Installation

To install this library, run:

```bash
$ npm install @ebondu/angular2-keycloak --save
```

## Development

Install the latest angular-cli

```bash
npm install -g @angular/cli
```

To generate all `*.js`, `*.js.map` and `*.d.ts` files:

```bash
$ ng build @ebondu/angular-keycloak --prod
```

All distribution files are located in ```dist/ebondu/angular2-keycloak```

## Usage

### Application setup

Declare Keycloak configuration / interceptor in angular app :

```javascript
import { KEYCLOAK_CONF, KEYCLOAK_INIT_OPTIONS, KeycloakInterceptor } from '@ebondu/angular-keycloak';

@NgModule({
  declarations: [
    AppComponent
  ],
  imports: [
    HttpClientModule,
    ...
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
       useClass: KeycloakInterceptor,
       multi: true,
     },
     ...
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }

```
Note that `keycloakInitOption` and `keycloakConfig` allow you to declare keycloak configuration and must be declared in your project (for example your environment file).
Configuration can also be loaded from file by providing a value for `KEYCLOAK_JSON_PATH` token.

````
export const keycloakInitOption: KeycloakInitOptions = {
    responseMode: KeycloakResponseMode.QUERY,
    flow: KeycloakFlow.STANDARD,
    // checkLoginIframe: true,
    // checkLoginIframeInterval: 10000,
    // onLoad: KeycloakOnLoad.CHECK_SSO
};

export const keycloakConfig: KeycloakConfiguration = {
    authServerUrl: 'https://localhost/auth',
    realm: 'master',
    clientId: 'your-app'
};
````

Then you can inject the keycloak service in your component to user the service
### Keycloak service
Example for login

```javascript
import { KeycloakService } from '@ebondu/angular-keycloak';
...

export class AppComponent { {

  public isAuthenticated: boolean;
  public profile: any;

  constructor(private keycloak: Keycloak) {
    this.keycloak.authenticationObs.subscribe(auth => {
      this.isAuthenticated = auth;
      this.parsedToken = this.keycloak.tokenParsed;
      console.info('APP: authentication status changed...');
    });
  }

  login() {
    this.keycloak.login({});
  }

  logout() {
    this.keycloak.logout({});
  }

  loadProfile() {
    this.keycloak.loadUserProfile().subscribe(profile => {
      this.profile = profile;
    });
  }

  ...
}
```
### HttpInterceptor
Please, use HttpClient interface to get access to Keycloak http proxy (authentication / authorization). 
Angular will inject the right provider class for you.

```javascript
import { HttpClient } from '@angular/common/http';
...

@Injectable()
export class MyClass {
    // Angular will inject the instance of the KeycloakHttp class
    constructor(private http: HttpClient) {}

    callAPI(): Observable<MyObject> {

      let headers = new Headers({'Accept' :'application/json'});
      let options: RequestOptionsArgs = { headers: headers, withCredentials: true };
        return this.http.get("http://localhost/myAPI/myMethod",  options)
            .map(res => res.json())
            .catch(err => handleError(err));
     }
     ...
}
```

To bypass the keycloak interceptor set `withCredentials: false`

## Example

See `project/angular6-example-app` or run 

```bash
ng serve angular6-example-app
```

## License

Apache2 © [ebondu](dev.ebondu@gmail.com)
# angular-keycloak
