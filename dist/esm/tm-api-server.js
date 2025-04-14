import cors from 'cors';
import express from 'express';
import jwt from 'jsonwebtoken';
import multer from 'multer';
const { TokenExpiredError } = jwt;
export class apiModule {
    constructor() {
        this.server = null;
    }
    init(server) {
        this.server = server;
        server.add_routes(this.define_routes());
        return this;
    }
    define_routes() {
        return [];
    }
}
export class apiError extends Error {
    constructor({ code, error, data, errors }) {
        let message;
        if (error === undefined || error === null) {
            message = '[Unknown error]';
        }
        else if (typeof code === 'number' && typeof error === 'string') {
            message = error;
        }
        else if (error && typeof error === 'object') {
            if ('parent' in error && error.parent && typeof error.parent.message === 'string') {
                message = error.parent.message;
            }
            else if ('message' in error && typeof error.message === 'string') {
                message = error.message;
            }
            else if (typeof error === 'string') {
                message = error;
            }
            else {
                message = String(error) || '[Unknown error]';
            }
        }
        else if (typeof error === 'string') {
            message = error;
        }
        else {
            message = String(error) || '[Unknown error]';
        }
        super(message);
        this.error = message;
        if (typeof code === 'number' && typeof error === 'string') {
            this.code = code;
            this.data = data !== undefined ? data : null;
            this.errors = errors !== undefined ? errors : {};
        }
        else {
            this.code = 500;
            this.data = null;
            this.errors = {};
        }
        if (error instanceof Error && error.stack) {
            this.stack = error.stack;
        }
    }
}
export class apiServer {
    constructor(config) {
        this.curreq = null;
        config.jwt_secret || (config.jwt_secret = '');
        config.upload_max || (config.upload_max = 30 * 1024 * 1024);
        config.upload_path || (config.upload_path = '');
        config.origins || (config.origins = []);
        this.config = config;
        this.router_v1 = express.Router();
        this.app = express();
        if (config.upload_path) {
            const upload = multer({ dest: config.upload_path });
            this.app.use(upload.any());
        }
        this.middlewares();
        this.app.use('/api/v1', this.router_v1);
        // add_swagger_ui(this.app);
    }
    guess_exception_text(error, defmsg = 'Unkown Error') {
        const msg = [];
        if (typeof error === 'string') {
            msg.push(error);
        }
        else {
            if (error && typeof error.message === 'string') {
                msg.push(error.message);
            }
            if (error && error.parent && typeof error.parent.message === 'string') {
                msg.push(error.parent.message);
            }
        }
        if (msg.length === 0) {
            return defmsg;
        }
        return msg.join('/');
    }
    async get_api_key(token) {
        return null;
    }
    async authorize(apireq, requiredClass) { }
    middlewares() {
        this.app.use(express.json());
        const corsOptions = {
            origin: (origin, callback) => {
                if (!origin) {
                    return callback(null, true);
                }
                if (this.config.origins && this.config.origins.length > 0) {
                    if (this.config.origins.includes(origin)) {
                        return callback(null, true);
                    }
                    return callback(new Error(`${origin} Not allowed by CORS`));
                }
                return callback(null, true);
            },
            credentials: true,
        };
        this.app.use(cors(corsOptions));
    }
    start() {
        this.app.listen(this.config.api_port, this.config.api_host, () => {
            console.log(`Server is running on http://${this.config.api_host}:${this.config.api_port}`);
        });
    }
    async verifyJWT(token) {
        if (!this.config.jwt_secret) {
            return { tokendata: undefined, error: 'JWT authentication disabled; no jwt_secret set' };
        }
        let td;
        try {
            td = jwt.verify(token, this.config.jwt_secret);
            if (!td) {
                throw new apiError({ code: 500, error: 'Unable to verify refresh token' });
            }
            if (!td.uid) {
                throw new apiError({ code: 500, error: 'Missing/bad userid in token' });
            }
        }
        catch (error) {
            if (error instanceof TokenExpiredError) {
                return { tokendata: undefined, error: 'Refresh token expired' };
            }
            else {
                return { tokendata: undefined, error: this.guess_exception_text(error) + ' -> (token verification)' };
            }
        }
        return { tokendata: td, error: undefined };
    }
    async authenticate(apireq, authType) {
        if (authType === 'none') {
            return null;
        }
        let token = null;
        const authHeader = apireq.req.headers.authorization;
        if (authHeader) {
            const match = authHeader.match(/^Bearer (.+)$/);
            if (match) {
                token = match[1];
            }
            else if (authType === 'yes') {
                throw new apiError({ code: 500, error: 'Authorization header must be a Bearer token' });
            }
        }
        if (token) {
            const m = token.match(/^apikey-(.+)$/);
            if (m) {
                const key = await this.get_api_key(m[1]);
                if (key) {
                    apireq.token = m[1];
                    return {
                        uid: key.uid,
                        domain: '',
                        fingerprint: '',
                        iat: 0,
                        exp: 0,
                    };
                }
                else {
                    throw new apiError({ code: 401, error: 'Invalid API Key' });
                }
            }
        }
        if (!token || token === null) {
            const access = apireq.req.cookies?.dat;
            if (access) {
                token = access;
            }
            else if (authType === 'yes') {
                throw new apiError({ code: 401, error: 'Authorization token is required (Bearer/cookie)' });
            }
        }
        if (!token) {
            if (authType === 'maybe') {
                return null;
            }
            else {
                throw new apiError({ code: 401, error: 'Unauthorized Access - requires authentication' });
            }
        }
        const { tokendata, error } = await this.verifyJWT(token);
        if (!tokendata) {
            throw new apiError({ code: 401, error: 'Unathorized Access - ' + error });
        }
        apireq.token = token;
        return tokendata;
    }
    handle_request(handler, auth) {
        return async (req, res, next) => {
            try {
                const apireq = (this.curreq = {
                    server: this,
                    req,
                    res,
                    token: '',
                    tokendata: null,
                });
                apireq.tokendata = await this.authenticate(apireq, auth.type);
                await this.authorize(apireq, auth.req);
                const [code, data = null, message = 'Success'] = await handler(apireq);
                res.status(code).json({ code, message, data });
            }
            catch (error) {
                if (error instanceof apiError) {
                    res.status(error.code).json({
                        code: error.code,
                        error: error.message,
                        data: error.data || null,
                        errors: error.errors || [],
                    });
                }
                else {
                    res.status(500).json({
                        code: 500,
                        error: this.guess_exception_text(error),
                        errors: [],
                    });
                }
            }
        };
    }
    add_routes(routes) {
        routes.forEach((route) => {
            const handler = this.handle_request(route.handler, route.auth);
            switch (route.method) {
                case 'get':
                    this.router_v1.get(route.path, handler);
                    break;
                case 'post':
                    this.router_v1.post(route.path, handler);
                    break;
                case 'put':
                    this.router_v1.put(route.path, handler);
                    break;
                case 'delete':
                    this.router_v1.delete(route.path, handler);
                    break;
                default:
                    throw new Error(`Unsupported method: ${route.method}`);
            }
        });
    }
}
export default apiServer;
