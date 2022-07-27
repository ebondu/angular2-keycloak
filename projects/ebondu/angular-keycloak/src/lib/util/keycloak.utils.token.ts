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

/**
 * Token utility
 */

import { fromByteArray } from 'base64-js';
import { sha256 } from 'js-sha256';

export class Token {

  static decodeToken(str: string): string {
    str = str.split('.')[1];

    str = str.replace('/-/g', '+');
    str = str.replace('/_/g', '/');
    switch (str.length % 4) {
      case 0:
        break;
      case 2:
        str += '==';
        break;
      case 3:
        str += '=';
        break;
      default:
        throw new Error('Invalid token');
    }

    str = (str + '===').slice(0, str.length + (str.length % 4));
    str = str.replace(/-/g, '+').replace(/_/g, '/');

    str = decodeURIComponent(escape(atob(str)));

    str = JSON.parse(str);
    return str;
  }

  static generateRandomData(len) {
    // use web crypto APIs if possible
    let array = null;
    const crypto = window.crypto;
    if (crypto && crypto.getRandomValues && window.Uint8Array) {
      array = new Uint8Array(len);
      crypto.getRandomValues(array);
      return array;
    }

    // fallback to Math random
    array = new Array(len);
    for (let j = 0; j < array.length; j++) {
      array[j] = Math.floor(256 * Math.random());
    }
    return array;
  }

  static generateCodeVerifier(len) {
    return Token.generateRandomString(len, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789');
  }

  static generateRandomString(len, alphabet) {
    const randomData = this.generateRandomData(len);
    const chars = new Array(len);
    for (let i = 0; i < len; i++) {
      chars[i] = alphabet.charCodeAt(randomData[i] % alphabet.length);
    }
    return String.fromCharCode.apply(null, chars);
  }

  static generatePkceChallenge(pkceMethod, codeVerifier) {
    switch (pkceMethod) {
      // The use of the "plain" method is considered insecure and therefore not supported.
      case 'S256':
        // hash codeVerifier, then encode as url-safe base64 without padding
        const hashBytes = new Uint8Array(sha256.arrayBuffer(codeVerifier));
        const encodedHash = fromByteArray(hashBytes)
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/\=/g, '');
        return encodedHash;
      default:
        throw new Error('Invalid value for pkceMethod');
    }
  }
}
