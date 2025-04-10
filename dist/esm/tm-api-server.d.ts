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
export declare class apiModule {
    protected server: IapiServer | null;
    init(server: apiServer): any;
    protected define_routes(): apiRoute[];
}
export declare class apiError extends Error {
    code: number;
    data: any;
    errors: Record<string, string>;
    constructor({ code, error, data, errors, }: {
        code: number;
        error: unknown;
        data?: any;
        errors?: Record<string, string>;
    });
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
    protected get_api_key(token: string): Promise<apiKey | null>;
    protected authorize(apireq: apiRequest, requiredClass: apiAuthClass): Promise<void>;
    private middlewares;
    start(): void;
    exception_error(error: any): string;
    private verifyJWT;
    private authenticate;
    private handle_request;
    add_routes(routes: apiRoute[]): void;
}
export default apiServer;
