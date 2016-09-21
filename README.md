# angular2-keycloak

## Installation

To install this library, run:

```bash
$ npm install angular2-keycloak --save
```

## Development

To generate all `*.js`, `*.js.map` and `*.d.ts` files:

```bash
$ npm run tsc
```

To lint all `*.ts` files:

```bash
$ npm run lint
```

## Usage

Declare Keycloak module in angular app :

```javascript
import { Ng2KeycloakModule } from 'angular2-keycloak';
...

@NgModule({
  declarations: [
    AppComponent
  ],
  imports: [
    Ng2KeycloakModule
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
import { Keycloak } from 'angular2-keycloak';
...

export class MyLoginClass {

  constructor( private keycloak: Keycloak) {
    this.keycloak.init({});
  }
  
  
  login(): void {
     Keycloak.login(true);
  }
  
  ...
}
```

To use keycloak http proxy (authentication / authorization)

```javascript
import { KeycloakHttp } from 'angular2-keycloak';
...

@Injectable()
export class MyClass {

    constructor(private http: KeycloakHttp) {

    }

    callAPI(): Observable<MyObject> {

      let headers = new Headers({'Accept' :'application/json'});
      let options: RequestOptionsArgs = { headers: headers };
        return this.http.get("http://localhost/myAPI/myMethod",  options)
            .map(res => res.json())
            .catch(err => handleError(err));
     }
     ...
}
```


## License

Apache2 © [emilienbondu](emilien.bondu@gmail.com)
# angular2-keycloak
