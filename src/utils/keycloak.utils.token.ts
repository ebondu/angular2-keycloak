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
