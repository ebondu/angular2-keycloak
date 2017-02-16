# angular2-keycloak example app

A simple angular2 / webpack2 + Keycloak Typescript lib example app inspired on the official angular2-product app.

App generated with [`angular2-webpack`](https://github.com/preboot/angular2-webpack/) 

### Quick start with Keycloak demo distribution (recommended)

This app will <b>replace</b> the original angular2-product app to re-use the pre-configured demo realm.

#### Run the demo distribution with examples

* Download and start the latest demo distribution [`demo distribution`](http://www.keycloak.org/downloads.html)

* Ensure the original angular2-product app works as expected [`angular2-product`](http://localhost:8080/angular2-product/)

#### Deploy the app

* From `angular2-webpack-product-app` :

```bash
# install the dependencies with npm
$ npm install

# package the app
$ npm run build


# package the app for deployment in demo server
$ mvn clean install
$ mvn wildfly:deploy
```

* Go to [`angular2-product`](http://localhost:8080/angular2-product/) to test the app. 

### Test with an existing keycloak server running

If you already have a configured Keycloak server (and not running locally on `8080` port) you can just :

* Edit `keycloak.json` from [`angular2-webpack-product-app/src/public/keycloak.json`](angular2-webpack-product-app/src/public/angular2-product/keycloak.json) and [`angular2-webpack-product-app/src/public/angular2-product/keycloak.json`](angular2-webpack-product-app/src/public/angular2-product/keycloak.json) according to your existing Keycloak configuration. 

Then install and start the app :

From `angular2-webpack-product-app` : 

```bash
# install the dependencies with npm
$ npm install

# start the server
$ npm start
```

* From the Keycloak admin panel, in the client settings fields, check if `Valid Redirect URIs` and `Web Origins` are set to `http://localhost:8080/*` and `http://localhost:8080`

Go to [`angular2-product`](http://localhost:8080/angular2-product/) in your browser.

## Usage 

* click on [`login`](login) will prompt the Keycloak login form.
* click on [`My profile`](myprofile) will load and display the user profile.

* click on [`Load product`](Load product) to load products from the demo service (to adapt when testing without demo distribution)

# License

[MIT](/LICENSE)
