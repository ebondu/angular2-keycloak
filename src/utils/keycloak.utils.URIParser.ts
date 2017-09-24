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
 * URI parser.
 */
export class URIParser {
  static initialParse(uriToParse: string, responseMode: string) {
    let baseUri: string = '';
    let queryString: string = '';
    let fragmentString: string = '';

    const questionMarkIndex = uriToParse.indexOf('?');
    let fragmentIndex = uriToParse.indexOf('#', questionMarkIndex + 1);
    if (questionMarkIndex === -1 && fragmentIndex === -1) {
      baseUri = uriToParse;
    } else if (questionMarkIndex !== -1) {
      baseUri = uriToParse.substring(0, questionMarkIndex);
      queryString = uriToParse.substring(questionMarkIndex + 1);
      if (fragmentIndex !== -1) {
        fragmentIndex = queryString.indexOf('#');
        fragmentString = queryString.substring(fragmentIndex + 1);
        queryString = queryString.substring(0, fragmentIndex);
      }
    } else {
      baseUri = uriToParse.substring(0, fragmentIndex);
      fragmentString = uriToParse.substring(fragmentIndex + 1);
    }

    return {
      'baseUri': baseUri,
      'queryString': queryString,
      'fragmentString': fragmentString
    };
  }

  static parseParams(paramString: string) {
    const result: any = {};
    const params = paramString.split('&');
    for (const pIt of params) {
      const p = pIt.split('=');
      const paramName = decodeURIComponent(p[0]);
      const paramValue = decodeURIComponent(p[1]);
      result[paramName] = paramValue;
    }
    return result;
  }

  static handleQueryParam(
    paramName: string,
    paramValue: string,
    oauth: any
  ): boolean {
    const supportedOAuthParams = [
      'code',
      'state',
      'error',
      'error_description'
    ];

    for (const paramNameIt of supportedOAuthParams) {
      if (paramName === paramNameIt) {
        oauth[paramName] = paramValue;
        return true;
      }
    }
    return false;
  }

  static parseUri(uriToParse: string, responseMode: string) {
    const parsedUri = this.initialParse(
      decodeURIComponent(uriToParse),
      responseMode
    );

    let queryParams: any = {};
    if (parsedUri.queryString) {
      queryParams = this.parseParams(parsedUri.queryString);
    }

    const oauth: any = { newUrl: parsedUri.baseUri };

    for (const param in queryParams) {
      if (param) {
        switch (param) {
          case 'redirect_fragment':
            oauth.fragment = queryParams[param];
            break;
          case 'prompt':
            oauth.prompt = queryParams[param];
            break;
          default:
            if (
              responseMode !== 'query' ||
              !this.handleQueryParam(param, queryParams[param], oauth)
            ) {
              oauth.newUrl +=
                (oauth.newUrl.indexOf('?') === -1 ? '?' : '&') +
                param +
                '=' +
                queryParams[param];
            }
            break;
        }
      }
    }

    if (responseMode === 'fragment') {
      let fragmentParams: any = {};
      if (parsedUri.fragmentString) {
        fragmentParams = this.parseParams(parsedUri.fragmentString);
      }
      for (const param in fragmentParams) {
        if (param) {
          oauth[param] = fragmentParams[param];
        }
      }
    }
    return oauth;
  }
}
