/*
 * Copyright 2022 ebondu and/or its affiliates
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
 * Check login Iframe utility
 */
export class KeycloakCheckLoginIframe {
  private iframe: any;
  private interval: number;
  private iframeSrc: string;

  constructor(private keycloak: KeycloakService, checkInterval: number) {
    this.interval = checkInterval;
    this.iframeSrc = this.keycloak.getRealmUrl() + '/protocol/openid-connect/login-status-iframe.html';
    this.initIframe();
  }

  initIframe() {
    this.iframe = document.createElement('iframe');
    this.iframe.setAttribute('src', this.iframeSrc);
    this.iframe.style.display = 'none';
    this.iframe.setAttribute('title', 'keycloak-session-iframe');
    document.body.appendChild(this.iframe);

    if (this.interval > 0) {
      this.iframe.onload = (() => {
        setTimeout(() => this.checkIframe(), this.interval);
      });
    }
    window.addEventListener('message', () => this.processCallbackMessage(event), false);
  }

  private checkIframe() {
    const msg = this.keycloak.keycloakConfig.clientId + ' ' + (!!this.keycloak.sessionId ? this.keycloak.sessionId : '');
    const origin = this.iframeSrc.substring(0, this.iframeSrc.indexOf('/', 8));

    // console.log('sending message to iframe ' + msg + ' origin :' + origin);
    this.iframe.contentWindow.postMessage(msg, origin);

    if (this.interval > 0) {
      setTimeout(() => this.checkIframe(), this.interval);
    }
  }

  private processCallbackMessage(event: any) {
    const origin = this.iframeSrc.substring(0, this.iframeSrc.indexOf('/', 8));
    // console.log('checking iframe message callback..' + event.data + ' ' + event.origin);
    if ((event.origin !== origin) || (this.iframe.contentWindow !== event.source)) {
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
