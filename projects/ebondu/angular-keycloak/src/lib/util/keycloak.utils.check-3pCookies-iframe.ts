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
 * 3Party cookie Iframe utility
 */
export class KeycloakCheck3pCookiesIframe {
  private iframe: any;
  private interval: number;
  private iframeSrc: string;
  private supportedBS: BehaviorSubject<boolean>;
  public supportedObs: Observable<boolean>;

  constructor(private keycloak: KeycloakService) {
    this.iframeSrc = this.keycloak.getRealmUrl() + '/protocol/openid-connect/3p-cookies/step1.html';
    this.supportedBS = new BehaviorSubject<any>(null);
    this.supportedObs = this.supportedBS.asObservable();
    this.initIframe();
  }

  initIframe() {
    this.iframe = document.createElement('iframe');
    this.iframe.setAttribute('src', this.iframeSrc);
    this.iframe.setAttribute('title', 'keycloak-3p-check-iframe' );
    this.iframe.style.display = 'none';
    document.body.appendChild(this.iframe);
    window.addEventListener('message', () => this.process3pCookieCallbackMessage(event), false);
  }

  private process3pCookieCallbackMessage(event: any) {
    // console.log('checking iframe message callback..' + event.data + ' ' + event.origin);
    if (this.iframe.contentWindow !== event.source) {
      // console.log('event is not coming from the iframe, ignoring it');
      return;
    }
    // console.log('Checking iframe message ' + event.data);
    if (event.data !== 'supported' && event.data !== 'unsupported') {
      return;
    }
    if (event.data === 'unsupported') {
      console.warn('[KEYCLOAK] 3rd party cookies aren\'t supported by this browser.' +
        ' checkLoginIframe and silent check-sso are not available.'
      );
      this.supportedBS.next(false);
    } else {
      this.supportedBS.next(true);
    }
    document.body.removeChild(this.iframe);
    window.removeEventListener('message', () => this.process3pCookieCallbackMessage(event));
  }
}
