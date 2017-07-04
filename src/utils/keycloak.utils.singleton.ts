/**
 * Created by emilienbondu on 04/07/2017.
 */
export class Lock
{
    private static _instance: Lock;

    private _aquired: boolean = false ;
    public static getInstance():Lock
    {
        return Lock._instance||(Lock._instance = new Lock());
    };

    public acquire() {
        this._aquired = true;
    }

    public release() {
        this._aquired = false;
    }

    public isAquired(): boolean {
        return this._aquired;
    }
}