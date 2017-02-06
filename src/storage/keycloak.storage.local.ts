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
 * To store Keycloak objects like tokens using a localStorage.
 */
export class LocalStorage {

    public clearExpired() {
        let time = new Date().getTime();
        for (let i = 1; i <= localStorage.length; i++) {
            let key = localStorage.key(i);
            if (key && key.indexOf('kc-callback-') === 0) {
                let value = localStorage.getItem(key);
                if (value) {
                    try {
                        let expires = JSON.parse(value).expires;
                        if (!expires || expires < time) {
                            localStorage.removeItem(key);
                        }
                    } catch (err) {
                        localStorage.removeItem(key);
                    }
                }
            }
        }
    }

    public get(state: string) {
        if (!state) {
            return;
        }

        let key = 'kc-callback-' + state;
        let value = localStorage.getItem(key);
        if (value) {
            localStorage.removeItem(key);
            value = JSON.parse(value);
        }

        this.clearExpired();
        return value;
    };

    public add(state: any) {
        this.clearExpired();

        let key = 'kc-callback-' + state.state;
        state.expires = new Date().getTime() + (60 * 60 * 1000);
        localStorage.setItem(key, JSON.stringify(state));
    };
}
