/*
 * Copyright 2017 ebondu and/or its affiliates
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
 * To store Keycloak objects like tokens using a cookie.
 */
export class CookieStorage {

    public get(state: string) {
        if (!state) {
            return;
        }

        let value = this.getCookie('kc-callback-' + state);
        this.setCookie('kc-callback-' + state, '', this.cookieExpiration(-100));
        if (value) {
            return JSON.parse(value);
        }
    };

    public add(state: any) {
        this.setCookie('kc-callback-' + state.state, JSON.stringify(state), this.cookieExpiration(60));
    };

    public removeItem(key: any) {
        this.setCookie(key, '', this.cookieExpiration(-100));
    };

    public cookieExpiration(minutes: number) {
        let exp = new Date();
        exp.setTime(exp.getTime() + (minutes * 60 * 1000));
        return exp;
    };

    public getCookie = function (key: any) {
        let name = key + '=';
        let ca = document.cookie.split(';');
        for (let i = 0; i < ca.length; i++) {
            let c = ca[i];
            while (c.charAt(0) === ' ') {
                c = c.substring(1);
            }
            if (c.indexOf(name) === 0) {
                return c.substring(name.length, c.length);
            }
        }
        return '';
    };

    public setCookie(key: string, value: string, expirationDate: Date) {
        let cookie = key + '=' + value + '; '
            + 'expires=' + expirationDate.toUTCString() + '; ';
        document.cookie = cookie;
    }
}
