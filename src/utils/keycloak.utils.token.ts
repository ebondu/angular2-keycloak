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
 * Token utility
 */
export class Token {

    static decodeToken(str:string):string {
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
                throw 'Invalid token';
        }

        str = (str + '===').slice(0, str.length + (str.length % 4));
        str = str.replace(/-/g, '+').replace(/_/g, '/');

        str = decodeURIComponent(atob(str));

        str = JSON.parse(str);
        return str;
    }
}
