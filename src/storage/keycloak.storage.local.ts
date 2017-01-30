
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
