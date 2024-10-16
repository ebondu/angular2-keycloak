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
 * Silent login check Iframe utility
 */
export class KeycloakSilentCheckLoginIframe {
  private iframe: any;
  private iframeSrc: string;

  constructor(private keycloak: KeycloakService, silentRedirectUri: string) {
    this.iframeSrc = this.keycloak.createLoginUrl({
      prompt: 'none',
      redirectUri: silentRedirectUri
    });
    this.initIframe();
  }

  initIframe() {
    this.iframe = document.createElement('iframe');
    this.iframe.setAttribute('src', this.iframeSrc);
    this.iframe.setAttribute('sandbox', 'allow-storage-access-by-user-activation allow-scripts allow-same-origin');
    this.iframe.style.display = 'none';
    this.iframe.setAttribute('title', 'keycloak-silent-check-sso');
    document.body.appendChild(this.iframe);
    window.addEventListener('message', () => this.processSilentLoginCallbackMessage(event), false);
  }

  private processSilentLoginCallbackMessage(event: any) {
    const origin = this.iframeSrc.substring(0, this.iframeSrc.indexOf('/', 8));
    // console.log('checking iframe message callback..' + event.data + ' ' + event.origin);
    if ((event.origin !== window.location.origin) || (this.iframe.contentWindow !== event.source)) {
      // console.log('event is not coming from the iframe, ignoring it');
      return;
    }
    const oauth = this.keycloak.parseCallback(event.data);
    if (!!oauth) {
      this.keycloak.processCallback(oauth).subscribe(() => console.log('Silent login ended'));
    }
    document.body.removeChild(this.iframe);
    window.removeEventListener('message', () => this.processSilentLoginCallbackMessage(event), false);
  }
}
