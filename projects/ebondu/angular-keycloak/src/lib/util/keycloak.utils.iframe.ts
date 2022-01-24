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
  private silentCheckSsoRedirectUri: string;

  constructor(private keycloak: KeycloakService, checkInterval: number, silentCheckSsoRedirectUri: string) {
    this.checkBS = new BehaviorSubject<boolean>(null);
    this.checkObs = this.checkBS.asObservable();
    this.interval = checkInterval;
    this.silentCheckSsoRedirectUri = silentCheckSsoRedirectUri;
    this.initIframe();
  }

  initIframe() {
    // console.log('Configuring login iframe...');
    this.iframe = document.createElement('iframe');
    this.iframe.onload = (() => {
      setTimeout(() => this.checkIframe(), this.interval);
    });

    // console.log('configuring iframe url to ' + this.silentCheckSsoRedirectUri);
    this.iframe.setAttribute('src', this.silentCheckSsoRedirectUri);
    this.iframe.style.display = 'none';
    document.body.appendChild(this.iframe);
    window.addEventListener('message', () => this.processCallbackMessage(event), false);
  }

  private checkIframe() {
    const msg = this.keycloak.keycloakConfig.clientId + ' ' + this.keycloak.sessionId;
    const origin = this.silentCheckSsoRedirectUri.substring(0, this.silentCheckSsoRedirectUri.indexOf('/', 8));

    // console.log('sending message to iframe ' + msg + ' origin :' + origin);
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
