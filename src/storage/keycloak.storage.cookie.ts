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
