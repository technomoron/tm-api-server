import { Application, Request, Response } from 'express';
import { JwtPayload } from 'jsonwebtoken';
export interface apiTokenData extends JwtPayload {
    uid: number;
    domain: string;
    fingerprint: string;
    iat: number;
    exp: number;
}
export interface apiRequest {
    server: any;
    req: Request;
    res: Response;
    tokendata?: apiTokenData | null;
    token?: string;
}
export type apiHandler = (apireq: apiRequest) => Promise<[number] | [number, any] | [number, any, string]>;
export type apiAuthType = 'none' | 'maybe' | 'yes';
export type apiAuthClass = 'any' | 'admin';
export interface apiKey {
    uid: number;
}
export type apiRoute = {
    method: 'get' | 'post' | 'put' | 'delete';
    path: string;
    handler: apiHandler;
    auth: {
        type: apiAuthType;
        req: apiAuthClass;
    };
};
export interface IapiServer {
    add_routes(routes: apiRoute[]): void;
}
export declare class apiModule<T extends IapiServer = IapiServer> {
    protected server: T | null;
    init(server: T): this;
    protected define_routes(): apiRoute[];
}
export interface apiErrorParams {
    code: number;
    error: any;
    data?: any;
    errors?: Record<string, string>;
}
export declare class apiError extends Error {
    code: number;
    error: string;
    data: any;
    errors: Record<string, string>;
    constructor({ code, error, data, errors }: apiErrorParams);
}
export interface apiServerConf {
    jwt_secret?: string;
    api_port: number;
    api_host: string;
    upload_path?: string;
    upload_max?: number;
    origins?: string[];
}
export declare class apiServer {
    app: Application;
    curreq: apiRequest | null;
    private router_v1;
    readonly config: apiServerConf;
    constructor(config: apiServerConf);
    guess_exception_text(error: any, defmsg?: string): string;
    protected get_api_key(token: string): Promise<apiKey | null>;
    protected authorize(apireq: apiRequest, requiredClass: apiAuthClass): Promise<void>;
    private middlewares;
    start(): void;
    private verifyJWT;
    private authenticate;
    private handle_request;
    add_routes(routes: apiRoute[]): void;
    api<T extends apiModule<IapiServer>>(ApiModuleClass: new () => T): this;
    dump_request(apireq: apiRequest): void;
}
export default apiServer;
