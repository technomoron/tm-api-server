"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.apiServer = exports.apiError = exports.apiModule = void 0;
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const cors_1 = __importDefault(require("cors"));
const express_1 = __importDefault(require("express"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const multer_1 = __importDefault(require("multer"));
const { TokenExpiredError } = jsonwebtoken_1.default;
class apiModule {
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
exports.apiModule = apiModule;
function guess_exception_text(error, defmsg = 'Unknown Error') {
    const msg = [];
    if (typeof error === 'string' && error.trim() !== '') {
        msg.push(error);
    }
    else if (error && typeof error === 'object') {
        if (typeof error.message === 'string' && error.message.trim() !== '') {
            msg.push(error.message);
        }
        if (error.parent && typeof error.parent.message === 'string' && error.parent.message.trim() !== '') {
            msg.push(error.parent.message);
        }
    }
    return msg.length > 0 ? msg.join(' / ') : defmsg;
}
class apiError extends Error {
    constructor({ code, message, data, errors }) {
        const msg = guess_exception_text(message, '[Unknown error (null/undefined)]');
        super(msg);
        this.message = msg;
        this.code = typeof code === 'number' ? code : 500;
        this.data = data !== undefined ? data : null;
        this.errors = errors !== undefined ? errors : {};
    }
}
exports.apiError = apiError;
class apiServer {
    constructor(config) {
        this.curreq = null;
        config.jwt_secret || (config.jwt_secret = '');
        config.upload_max || (config.upload_max = 30 * 1024 * 1024);
        config.upload_path || (config.upload_path = '');
        config.origins || (config.origins = []);
        this.config = config;
        this.router_v1 = express_1.default.Router();
        this.app = (0, express_1.default)();
        if (config.upload_path) {
            const upload = (0, multer_1.default)({ dest: config.upload_path });
            this.app.use(upload.any());
        }
        this.middlewares();
        this.app.use('/api/v1', this.router_v1);
        // add_swagger_ui(this.app);
    }
    guess_exception_text(error, defmsg = 'Unkown Error') {
        return guess_exception_text(error, defmsg);
    }
    async get_api_key(token) {
        return null;
    }
    async authorize(apireq, requiredClass) { }
    middlewares() {
        this.app.use(express_1.default.json());
        this.app.use((0, cookie_parser_1.default)());
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
        this.app.use((0, cors_1.default)(corsOptions));
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
            td = jsonwebtoken_1.default.verify(token, this.config.jwt_secret);
            if (!td) {
                throw new apiError({ code: 500, message: 'Unable to verify refresh token' });
            }
            if (!td.uid) {
                throw new apiError({ code: 500, message: 'Missing/bad userid in token' });
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
        if (authHeader?.startsWith('Bearer ')) {
            token = authHeader.slice(7).trim();
        }
        else if (authType === 'yes' && !authHeader) {
            throw new apiError({ code: 401, message: 'Authorization header is missing or invalid' });
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
                    throw new apiError({ code: 401, message: 'Invalid API Key' });
                }
            }
        }
        if (!token || token === null) {
            const access = apireq.req.cookies?.dat;
            if (access) {
                token = access;
            }
            else if (authType === 'yes') {
                throw new apiError({ code: 401, message: 'Authorization token is required (Bearer/cookie)' });
            }
        }
        if (!token) {
            if (authType === 'maybe') {
                return null;
            }
            else {
                throw new apiError({ code: 401, message: 'Unauthorized Access - requires authentication' });
            }
        }
        const { tokendata, error } = await this.verifyJWT(token);
        if (!tokendata) {
            throw new apiError({ code: 401, message: 'Unathorized Access - ' + error });
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
                        message: error.message,
                        data: error.data || null,
                        errors: error.errors || [],
                    });
                }
                else {
                    res.status(500).json({
                        code: 500,
                        message: this.guess_exception_text(error),
                        data: null,
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
    api(ApiModuleClass) {
        const moduleInstance = new ApiModuleClass();
        moduleInstance.init(this); // docServer should be a valid IapiServer.
        return this;
    }
    dump_request(apireq) {
        const req = apireq.req;
        console.log('--- Incoming Request ---');
        console.log('URL:', req.originalUrl);
        console.log('Method:', req.method);
        console.log('Query Params:', req.query);
        console.log('Body Params:', req.body);
        console.log('Cookies:', req.cookies);
        console.log('Headers:', req.headers);
        console.log('------------------------');
    }
}
exports.apiServer = apiServer;
exports.default = apiServer;
