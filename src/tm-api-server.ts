import cors from 'cors';
import express, { Application, Request, Response, NextFunction, Router } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';
import multer from 'multer';

const { TokenExpiredError } = jwt;

// import { add_swagger_ui } from '../swagger';

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

// Forward reference for apiServer to avoid circular error.
export interface IapiServer {
	add_routes(routes: apiRoute[]): void;
}

export class apiModule<T extends IapiServer = IapiServer> {
	protected server: T | null = null;

	init(server: T): this {
		this.server = server;
		server.add_routes(this.define_routes());
		return this;
	}

	protected define_routes(): apiRoute[] {
		return [];
	}
}

export interface apiErrorParams {
	code: number;
	error: any;
	data?: any;
	errors?: Record<string, string>;
}

export class apiError extends Error {
	public code: number;
	public error: string;
	public data: any;
	public errors: Record<string, string>;

	constructor({ code, error, data, errors }: apiErrorParams) {
		let message: string;
		if (error === undefined || error === null) {
			message = '[Unknown error]';
		} else if (typeof code === 'number' && typeof error === 'string') {
			message = error;
		} else if (error && typeof error === 'object') {
			if ('parent' in error && error.parent && typeof error.parent.message === 'string') {
				message = error.parent.message;
			} else if ('message' in error && typeof error.message === 'string') {
				message = error.message;
			} else if (typeof error === 'string') {
				message = error;
			} else {
				message = String(error) || '[Unknown error]';
			}
		} else if (typeof error === 'string') {
			message = error;
		} else {
			message = String(error) || '[Unknown error]';
		}

		super(message);

		this.error = message;
		if (typeof code === 'number' && typeof error === 'string') {
			this.code = code;
			this.data = data !== undefined ? data : null;
			this.errors = errors !== undefined ? errors : {};
		} else {
			this.code = 500;
			this.data = null;
			this.errors = {};
		}

		if (error instanceof Error && error.stack) {
			this.stack = error.stack;
		}
	}
}

export interface apiServerConf {
	jwt_secret?: string;
	api_port: number;
	api_host: string;
	upload_path?: string;
	upload_max?: number;
	origins?: string[];
}

export class apiServer {
	public app: Application;
	public curreq: apiRequest | null = null;
	private router_v1: Router;
	public readonly config: apiServerConf;

	constructor(config: apiServerConf) {
		config.jwt_secret ||= '';
		config.upload_max ||= 30 * 1024 * 1024;
		config.upload_path ||= '';
		config.origins ||= [];

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

	public guess_exception_text(error: any, defmsg: string = 'Unkown Error') {
		const msg = [];

		if (typeof error === 'string') {
			msg.push(error);
		} else {
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

	protected async get_api_key(token: string): Promise<apiKey | null> {
		return null;
	}

	protected async authorize(apireq: apiRequest, requiredClass: apiAuthClass) {}

	private middlewares() {
		this.app.use(express.json());

		const corsOptions = {
			origin: (origin: any, callback: any) => {
				if (!origin) {
					return callback(null, true);
				}
				if (this.config.origins && this.config.origins.length > 0 && this.config.origins.includes(origin)) {
					return callback(null, true);
				}
				return callback(new Error(`${origin} Not allowed by CORS`));
			},
			credentials: true,
		};

		this.app.use(cors(corsOptions));
	}

	public start() {
		this.app.listen(this.config.api_port, this.config.api_host, () => {
			console.log(`Server is running on http://${this.config.api_host}:${this.config.api_port}`);
		});
	}

	private async verifyJWT(
		token: string
	): Promise<{ tokendata: apiTokenData | undefined; error: string | undefined }> {
		if (!this.config.jwt_secret) {
			return { tokendata: undefined, error: 'JWT authentication disabled; no jwt_secret set' };
		}
		let td: apiTokenData;
		try {
			td = jwt.verify(token, this.config.jwt_secret) as apiTokenData;
			if (!td) {
				throw new apiError({ code: 500, error: 'Unable to verify refresh token' });
			}
			if (!td.uid) {
				throw new apiError({ code: 500, error: 'Missing/bad userid in token' });
			}
		} catch (error) {
			if (error instanceof TokenExpiredError) {
				return { tokendata: undefined, error: 'Refresh token expired' };
			} else {
				return { tokendata: undefined, error: this.guess_exception_text(error) + ' -> (token verification)' };
			}
		}
		return { tokendata: td, error: undefined };
	}

	private async authenticate(apireq: apiRequest, authType: apiAuthType): Promise<apiTokenData | null> {
		if (authType === 'none') {
			return null;
		}
		let token: string | null = null;
		const authHeader = apireq.req.headers.authorization;
		if (authHeader) {
			const match = authHeader.match(/^Bearer (.+)$/);
			if (match) {
				token = match[1];
			} else if (authType === 'yes') {
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
				} else {
					throw new apiError({ code: 401, error: 'Invalid API Key' });
				}
			}
		}

		if (!token || token === null) {
			const access = apireq.req.cookies?.dat;
			if (access) {
				token = access;
			} else if (authType === 'yes') {
				throw new apiError({ code: 401, error: 'Authorization token is required (Bearer/cookie)' });
			}
		}

		if (!token) {
			if (authType === 'maybe') {
				return null;
			} else {
				throw new apiError({ code: 401, error: 'Unauthorized Access - requires authentication' });
			}
		}
		const { tokendata, error } = await this.verifyJWT(token!);
		if (!tokendata) {
			throw new apiError({ code: 401, error: 'Unathorized Access - ' + error });
		}

		apireq.token = token;

		return tokendata;
	}

	private handle_request(handler: apiHandler, auth: { type: apiAuthType; req: apiAuthClass }) {
		return async (req: Request, res: Response, next: NextFunction) => {
			try {
				const apireq: apiRequest = (this.curreq = {
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
			} catch (error) {
				if (error instanceof apiError) {
					res.status(error.code).json({
						code: error.code,
						error: error.message,
						data: error.data || null,
						errors: error.errors || [],
					});
				} else {
					res.status(500).json({
						code: 500,
						error: this.guess_exception_text(error),
						errors: [],
					});
				}
			}
		};
	}

	public add_routes(routes: apiRoute[]) {
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
