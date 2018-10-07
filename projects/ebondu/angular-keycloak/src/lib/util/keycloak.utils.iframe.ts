/*
 * Copyright 2018 ebondu and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { KeycloakService } from '../service/keycloak.service';
import { BehaviorSubject, Observable } from 'rxjs';

/**
 * Iframe utility
 */
export class KeycloakCheckLoginIframe {

  public checkObs: Observable<boolean>;
  private iframe: any;
  private iframeOrigin: any;
  private interval: number;
  private checkBS: BehaviorSubject<boolean>;

  constructor(private keycloak: KeycloakService, checkInterval: number) {
    this.checkBS = new BehaviorSubject<boolean>(null);
    this.checkObs = this.checkBS.asObservable();
    this.interval = checkInterval;
    this.initIframe();
  }

  initIframe() {
    // console.log('Configuring login iframe...');
    this.iframe = document.createElement('iframe');
    this.iframe.onload = (() => {
      const realmUrl = this.keycloak.getRealmUrl();

      if (realmUrl.charAt(0) === '/') {
        if (!window.location.origin) {
          this.iframeOrigin = window.location.protocol
            + '//' + window.location.hostname
            + (window.location.port ? ': ' + window.location.port : '');
        } else {
          this.iframeOrigin = window.location.origin;
        }
      } else {
        this.iframeOrigin = realmUrl.substring(0, realmUrl.indexOf('/', 8));
      }
      // console.log('login iframe LOADED');
      // console.log('contentWindow :', this.iframe.contentWindow);
      setTimeout(() => this.checkIframe(), this.interval);
    });

    const src = this.keycloak.getRealmUrl() + '/protocol/openid-connect/login-status-iframe.html';
    // console.log('configuring iframe url to ' + src);
    this.iframe.setAttribute('src', src);
    this.iframe.style.display = 'none';
    document.body.appendChild(this.iframe);
    window.addEventListener('message', () => this.processCallbackMessage(event), false);
  }

  private checkIframe() {
    const msg = this.keycloak.keycloakConfig.clientId + ' ' + this.keycloak.sessionId;
    const origin = this.iframeOrigin;

    // // console.log('sending message to iframe ' + msg + ' origin :' + origin);
    this.iframe.contentWindow.postMessage(msg, origin);
    setTimeout(() => this.checkIframe(), this.interval);
  }

  private processCallbackMessage(event: any) {
    // console.log('checking iframe message callback..' + event.data + ' ' + event.origin);
    if ((event.origin !== this.iframeOrigin) || (this.iframe.contentWindow !== event.source)) {
      // console.log('event is not coming from the iframe, ignoring it');
      return;
    }
    if (!(event.data === 'unchanged' || event.data === 'changed' || event.data === 'error')) {
      // console.log('unknown event data, ignoring it');
      return;
    }

    if (event.data !== 'unchanged') {
      // console.log('event from the iframe, and data changed, clearing tokens');
      this.keycloak.clearToken({});
    }
  }
}
