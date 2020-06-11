/**
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import {
	ResponseMessage,
	ConfigInterface,
	ResponseModeTypes,
	TokenResponseInterface,
	TokenRequestHeader,
	AuthenticatedUserInterface,
	SignInResponse,
	MessageType,
	AccountSwitchRequestParams,
} from "./models";
import {
	INIT,
	SIGN_IN,
	SERVICE_RESOURCES,
	SIGNED_IN,
	AUTH_REQUIRED,
	AUTH_CODE,
	API_CALL,
	LOGOUT,
	SWITCH_ACCOUNTS,
} from "./constants";
import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse, AxiosError } from "axios";
import { getJWKForTheIdToken, isValidIdToken, getCodeVerifier, getCodeChallenge } from "./utils";
import { OIDC_SCOPE } from "./constants/token";

class OAuthWorker {
	private authorizationType?: string;
	private callbackURL: string;
	private clientHost: string;
	private clientID: string;
	private clientSecret: string;
	private consentDenied: boolean;
	private enablePKCE: boolean;
	private prompt: string;
	private responseMode: ResponseModeTypes;
	private requestedScope: string[];
	private serverOrigin: string;
	private tenant: string;
	private tenantPath: string;
	private baseUrls: string[];
	private token: string;
	private isOpConfigInitiated: boolean;
	private authorizeEndpoint: string;
	private tokenEndpoint: string;
	private endSessionEndpoint: string;
	private jwksUri: string;
	private revokeTokenEndpoint: string;
	private issuer: string;
	private authorizationCode: string;
	private pkceCodeVerifier: string;
	private accessTokenExpiresIn: string;
	private accessTokenIssuedAt: string;
	private displayName: string;
	private email: string;
	private idToken: string;
	private refreshToken: string;
	private tokenType: string;
	private userName: string;
	private allowedScope: string;
	private httpClient: AxiosInstance;

	private refreshTimer: number;

	constructor(config: ConfigInterface) {
		this.authorizationType = config.authorizationType;
		this.callbackURL = config.callbackURL;
		this.clientHost = config.clientHost;
		this.clientID = config.clientID;
		this.clientSecret = config.clientSecret;
		this.consentDenied = config.consentDenied;
		this.enablePKCE = config.enablePKCE;
		this.prompt = config.prompt;
		this.responseMode = config.responseMode;
		this.requestedScope = config.scope;
		this.serverOrigin = config.serverOrigin;
		this.tenant = config.tenant ?? "";
		this.tenantPath = config.tenantPath;
		this.baseUrls = config.baseUrls;

		this.httpClient = axios.create({
			withCredentials: true,
		});

		this.httpClient.interceptors.request.use(
			(config) => {
				config.headers = {
					...config.headers,
					Authorization: `Bearer ${this.token}`,
				};

				return config;
			},
			(error) => {
				return Promise.reject(error);
			}
		);
	}

	setIsOpConfigInitiated(status: boolean) {
		this.isOpConfigInitiated = status;
	}

	doesTokenExist() {
		if (this.token) {
			return true;
		}

		return false;
	}

	setAuthorizationCode(authCode: string) {
		this.authorizationCode = authCode;
	}

	initOPConfiguration(forceInit?: boolean): Promise<any> {
		if (!forceInit && this.isOpConfigInitiated) {
			return Promise.resolve();
		}

		return axios
			.get(this.serverOrigin + this.tenant + SERVICE_RESOURCES.wellKnown)
			.then((response) => {
				if (response.status !== 200) {
					return Promise.reject(
						new Error(
							"Failed to load OpenID provider configuration from: " +
								this.serverOrigin +
								this.tenant +
								SERVICE_RESOURCES.wellKnown
						)
					);
				}

				this.authorizeEndpoint = response.data.authorization_endpoint;
				this.tokenEndpoint = response.data.token_endpoint;
				this.endSessionEndpoint = response.data.end_session_endpoint;
				this.jwksUri = response.data.jwks_uri;
				this.revokeTokenEndpoint =
					response.data.token_endpoint.substring(0, response.data.token_endpoint.lastIndexOf("token")) +
					"revoke";
				this.issuer = response.data.issuer;
				this.setIsOpConfigInitiated(true);

				return Promise.resolve(
					"Initialized OpenID Provider configuration from: " +
						this.serverOrigin +
						this.tenant +
						SERVICE_RESOURCES.wellKnown
				);
			})
			.catch(() => {
				this.authorizeEndpoint = this.serverOrigin + SERVICE_RESOURCES.authorize;
				this.tokenEndpoint = this.serverOrigin + SERVICE_RESOURCES.token;
				this.revokeTokenEndpoint = this.serverOrigin + SERVICE_RESOURCES.revoke;
				this.endSessionEndpoint = this.serverOrigin + SERVICE_RESOURCES.logout;
				this.jwksUri = this.serverOrigin + this.tenant + SERVICE_RESOURCES.jwks;
				this.issuer = this.serverOrigin + SERVICE_RESOURCES.token;
				this.tenant = this.tenant;
				this.setIsOpConfigInitiated(true);

				return Promise.resolve(
					new Error(
						"Initialized OpenID Provider configuration from default configuration." +
							"Because failed to access welknown endpoint: " +
							this.serverOrigin +
							this.tenant +
							SERVICE_RESOURCES.wellKnown
					)
				);
			});
	}

	private getTokenRequestHeaders(clientHost: string): TokenRequestHeader {
		return {
			Accept: "application/json",
			"Access-Control-Allow-Origin": clientHost,
			"Content-Type": "application/x-www-form-urlencoded",
		};
	}

	setPkceCodeVerifier(pkce: string) {
		this.pkceCodeVerifier = pkce;
	}

	private validateIdToken(clientID: string, idToken: string, serverOrigin: string): Promise<any> {
		const jwksEndpoint = this.jwksUri;

		if (!jwksEndpoint || jwksEndpoint.trim().length === 0) {
			return Promise.reject("Invalid JWKS URI found.");
		}
		return axios
			.get(jwksEndpoint)
			.then((response) => {
				if (response.status !== 200) {
					return Promise.reject(new Error("Failed to load public keys from JWKS URI: " + jwksEndpoint));
				}

				const jwk = getJWKForTheIdToken(idToken.split(".")[0], response.data.keys);

				let issuer = this.issuer;

				if (!issuer || issuer.trim().length === 0) {
					issuer = serverOrigin + SERVICE_RESOURCES.token;
				}

				const validity = isValidIdToken(
					idToken,
					jwk,
					clientID,
					issuer,
					this.getAuthenticatedUser(idToken).username
				);

				return Promise.resolve(validity);
			})
			.catch((error) => {
				return Promise.reject(error.response);
			});
	}

	sendTokenRequest(): Promise<TokenResponseInterface> {
		const tokenEndpoint = this.tokenEndpoint;

		if (!tokenEndpoint || tokenEndpoint.trim().length === 0) {
			return Promise.reject(new Error("Invalid token endpoint found."));
		}

		const body = [];
		body.push(`client_id=${this.clientID}`);

		if (this.clientSecret && this.clientSecret.trim().length > 0) {
			body.push(`client_secret=${this.clientSecret}`);
		}

		const code = this.authorizationCode;
		this.authorizationCode = null;
		body.push(`code=${code}`);

		body.push("grant_type=authorization_code");
		body.push(`redirect_uri=${this.callbackURL}`);

		if (this.enablePKCE) {
			body.push(`code_verifier=${this.pkceCodeVerifier}`);
			this.pkceCodeVerifier = null;
		}

		return axios
			.post(tokenEndpoint, body.join("&"), { headers: this.getTokenRequestHeaders(this.clientHost) })
			.then((response) => {
				if (response.status !== 200) {
					return Promise.reject(
						new Error("Invalid status code received in the token response: " + response.status)
					);
				}
				return this.validateIdToken(this.clientID, response.data.id_token, this.serverOrigin).then((valid) => {
					if (valid) {
						const tokenResponse: TokenResponseInterface = {
							accessToken: response.data.access_token,
							expiresIn: response.data.expires_in,
							idToken: response.data.id_token,
							refreshToken: response.data.refresh_token,
							scope: response.data.scope,
							tokenType: response.data.token_type,
						};

						return Promise.resolve(tokenResponse);
					}

					return Promise.reject(
						new Error("Invalid id_token in the token response: " + response.data.id_token)
					);
				});
			})
			.catch((error) => {
				return Promise.reject(error.response);
			});
	}

	getAuthenticatedUser(idToken: string): AuthenticatedUserInterface {
		const payload = JSON.parse(atob(idToken.split(".")[1]));
		const emailAddress = payload.email ? payload.email : null;

		return {
			displayName: payload.preferred_username ? payload.preferred_username : payload.sub,
			email: emailAddress,
			username: payload.sub,
		};
	}

	sendAuthorizationRequest = (): string => {
		const authorizeEndpoint = this.authorizeEndpoint;

		if (!authorizeEndpoint || authorizeEndpoint.trim().length === 0) {
			throw new Error("Invalid authorize endpoint found.");
		}

		let authorizeRequest = authorizeEndpoint + "?response_type=code&client_id=" + this.clientID;

		let scope = OIDC_SCOPE;

		if (this.requestedScope && this.requestedScope.length > 0) {
			if (!this.requestedScope.includes(OIDC_SCOPE)) {
				this.requestedScope.push(OIDC_SCOPE);
			}
			scope = this.requestedScope.join(" ");
		}

		authorizeRequest += "&scope=" + scope;
		authorizeRequest += "&redirect_uri=" + this.callbackURL;

		if (this.responseMode) {
			authorizeRequest += "&response_mode=" + this.responseMode;
		}

		if (this.enablePKCE) {
			const codeVerifier = getCodeVerifier();
			const codeChallenge = getCodeChallenge(codeVerifier);
			this.pkceCodeVerifier = codeVerifier;
			authorizeRequest += "&code_challenge_method=S256&code_challenge=" + codeChallenge;
		}

		if (this.prompt) {
			authorizeRequest += "&prompt=" + this.prompt;
		}

		return authorizeRequest;
	};

	private initUserSession(
		tokenResponse: TokenResponseInterface,
		authenticatedUser: AuthenticatedUserInterface
	): void {
		this.token = tokenResponse.accessToken;
		this.accessTokenExpiresIn = tokenResponse.expiresIn;
		this.accessTokenIssuedAt = (Date.now() / 1000).toString();
		this.displayName = authenticatedUser.displayName;
		this.email = authenticatedUser.email;
		this.idToken = tokenResponse.idToken;
		this.allowedScope = tokenResponse.scope;
		this.refreshToken = tokenResponse.refreshToken;
		this.tokenType = tokenResponse.tokenType;
		this.userName = authenticatedUser.username;

		this.refreshTimer = setTimeout(() => {
			this.refreshAccessToken()
				.then((response) => {})
				.catch((error) => {
					console.error(error?.response);
				});
		}, (parseInt(this.accessTokenExpiresIn) - 10) * 1000);
	}

	private destroyUserSession(): void {
		this.token = null;
		this.accessTokenExpiresIn = null;
		this.accessTokenIssuedAt = null;
		this.displayName = null;
		this.email = null;
		this.idToken = null;
		this.allowedScope = null;
		this.refreshToken = null;
		this.tokenType = null;
		this.userName = null;

		clearTimeout(this.refreshTimer);
		this.refreshTimer = null;
	}

	sendSignInRequest(): Promise<SignInResponse> {
		if (this.authorizationCode) {
			return this.sendTokenRequest()
				.then((response: TokenResponseInterface) => {
					try {
						this.initUserSession(response, this.getAuthenticatedUser(response.idToken));
					} catch (error) {
						throw Error(error);
					}
					return Promise.resolve({ type: SIGNED_IN } as SignInResponse);
				})
				.catch((error) => {
					if (error.response && error.response.status === 400) {
						return Promise.resolve({
							type: AUTH_REQUIRED,
							code: this.sendAuthorizationRequest(),
							pkce: this.pkceCodeVerifier,
						});
					}

					return Promise.reject(error);
				});
		} else {
			return Promise.resolve({
				type: AUTH_REQUIRED,
				code: this.sendAuthorizationRequest(),
				pkce: this.pkceCodeVerifier,
			});
		}
	}

	private sendRefreshTokenRequest(): Promise<TokenResponseInterface> {
		const tokenEndpoint = this.tokenEndpoint;

		if (!tokenEndpoint || tokenEndpoint.trim().length === 0) {
			return Promise.reject("Invalid token endpoint found.");
		}

		const body = [];
		body.push(`client_id=${this.clientID}`);
		body.push(`refresh_token=${this.refreshToken}`);
		body.push("grant_type=refresh_token");

		return axios
			.post(tokenEndpoint, body.join("&"), { headers: this.getTokenRequestHeaders(this.clientHost) })
			.then((response) => {
				if (response.status !== 200) {
					return Promise.reject(
						new Error("Invalid status code received in the refresh token response: " + response.status)
					);
				}

				return this.validateIdToken(this.clientID, response.data.id_token, this.serverOrigin).then((valid) => {
					if (valid) {
						const tokenResponse: TokenResponseInterface = {
							accessToken: response.data.access_token,
							expiresIn: response.data.expires_in,
							idToken: response.data.id_token,
							refreshToken: response.data.refresh_token,
							scope: response.data.scope,
							tokenType: response.data.token_type,
						};

						return Promise.resolve(tokenResponse);
					}
					return Promise.reject(
						new Error("Invalid id_token in the token response: " + response.data.id_token)
					);
				});
			})
			.catch((error) => {
				return Promise.reject(error.response);
			});
	}

	private sendRevokeTokenRequest(): Promise<any> {
		const revokeTokenEndpoint = this.revokeTokenEndpoint;

		if (!revokeTokenEndpoint || revokeTokenEndpoint.trim().length === 0) {
			return Promise.reject("Invalid revoke token endpoint found.");
		}

		const body = [];
		body.push(`client_id=${this.clientID}`);
		body.push(`token=${this.token}`);
		body.push("token_type_hint=access_token");

		return axios
			.post(revokeTokenEndpoint, body.join("&"), {
				headers: this.getTokenRequestHeaders(this.clientHost),
				withCredentials: true,
			})
			.then((response) => {
				if (response.status !== 200) {
					return Promise.reject(
						new Error("Invalid status code received in the revoke token response: " + response.status)
					);
				}

				this.destroyUserSession();
				return Promise.resolve(response);
			})
			.catch((error) => {
				return Promise.reject(error.response);
			});
	}

	private sendAccountSwitchRequest(requestParams: AccountSwitchRequestParams): Promise<TokenResponseInterface> {
		const tokenEndpoint = this.tokenEndpoint;

		if (!tokenEndpoint || tokenEndpoint.trim().length === 0) {
			return Promise.reject(new Error("Invalid token endpoint found."));
		}

		let scope = OIDC_SCOPE;

		if (this.requestedScope && this.requestedScope.length > 0) {
			if (!this.requestedScope.includes(OIDC_SCOPE)) {
				this.requestedScope.push(OIDC_SCOPE);
			}
			scope = this.requestedScope.join(" ");
		}

		const body = [];
		body.push("grant_type=account_switch");
		body.push(`username=${requestParams.username}`);
		body.push(`userstore-domain=${requestParams["userstore-domain"]}`);
		body.push(`tenant-domain=${requestParams["tenant-domain"]}`);
		body.push(`token=${this.token}`);
		body.push(`scope=${scope}`);
		body.push(`client_id=${this.clientID}`);

		return axios
			.post(tokenEndpoint, body.join("&"), { headers: this.getTokenRequestHeaders(this.clientHost) })
			.then((response) => {
				if (response.status !== 200) {
					return Promise.reject(
						new Error("Invalid status code received in the token response: " + response.status)
					);
				}

				return this.validateIdToken(this.clientID, response.data.id_token, this.serverOrigin).then((valid) => {
					if (valid) {
						const tokenResponse: TokenResponseInterface = {
							accessToken: response.data.access_token,
							expiresIn: response.data.expires_in,
							idToken: response.data.id_token,
							refreshToken: response.data.refresh_token,
							scope: response.data.scope,
							tokenType: response.data.token_type,
						};
						return Promise.resolve(tokenResponse);
					}

					return Promise.reject(
						new Error("Invalid id_token in the token response: " + response.data.id_token)
					);
				});
			})
			.catch((error) => {
				return Promise.reject(error);
			});
	}

	refreshAccessToken(): Promise<boolean> {
		return new Promise((resolve, reject) => {
			this.sendRefreshTokenRequest()
				.then((response) => {
					this.initUserSession(response, this.getAuthenticatedUser(response.idToken));
					resolve(true);
				})
				.catch((error) => {
					reject(error);
				});
		});
	}

	switchAccount(requestParams: AccountSwitchRequestParams): Promise<boolean> {
		return new Promise((resolve, reject) => {
			this.sendAccountSwitchRequest(requestParams)
				.then((response) => {
					this.initUserSession(response, this.getAuthenticatedUser(response.idToken));
					resolve(true);
				})
				.catch((error) => {
					reject(error);
				});
		});
	}

	logout(): Promise<boolean> {
		return new Promise((resolve, reject) => {
			this.sendRevokeTokenRequest()
				.then((response) => {
					resolve(true);
				})
				.catch((error) => {
					reject(error);
				});
		});
	}

	callAPI(config: AxiosRequestConfig): Promise<AxiosResponse> {
		let matches = false;
		this.baseUrls.forEach((baseUrl) => {
			if (config.url.startsWith(baseUrl)) {
				matches = true;
			}
		});

		if (matches) {
			return this.httpClient(config)
				.then((response: AxiosResponse) => {
					return Promise.resolve(response);
				})
				.catch((error: AxiosError) => {
					if (error?.response?.status === 401) {
						clearTimeout(this.refreshTimer);
						this.refreshTimer = null;

						return this.refreshAccessToken()
							.then((response) => {
								return this.httpClient(config)
									.then((response) => {
										return Promise.resolve(response);
									})
									.catch((error) => {
										return Promise.reject(error?.response);
									});
							})
							.catch((error) => {
								return Promise.reject(error);
							});
					}
					return Promise.reject(error?.response);
				});
		} else {
			return Promise.reject("The provided URL is illegal.");
		}
	}
}

let oAuthWorker: OAuthWorker;

onmessage = ({ data, ports }: { data: { type: MessageType; data: any }; ports: readonly MessagePort[] }) => {
	const port = ports[0];

	switch (data.type) {
		case INIT:
			try {
				oAuthWorker = new OAuthWorker(data.data);
				port.postMessage({ success: true });
			} catch (error) {
				port.postMessage({ sucess: false, error: error });
			}
			break;
		case SIGN_IN:
			if (oAuthWorker.doesTokenExist()) {
				port.postMessage({ success: true, data: { type: SIGNED_IN } });
			} else {
				oAuthWorker
					.initOPConfiguration()
					.then(() => {
						oAuthWorker
							.sendSignInRequest()
							.then((response: SignInResponse) => {
								if (response.type === SIGNED_IN) {
									port.postMessage({ success: true, data: { type: SIGNED_IN } });
								} else {
									port.postMessage({
										success: true,
										data: { type: AUTH_REQUIRED, code: response.code, pkce: response.pkce },
									});
								}
							})
							.catch((error) => {
								port.postMessage({ success: false, error: error });
							});
					})
					.catch((error) => {
						port.postMessage({ sucess: false, error: error });
					});
			}
			break;
		case AUTH_CODE:
			oAuthWorker.setAuthorizationCode(data.data.code);

			if (data.data.pkce) {
				oAuthWorker.setPkceCodeVerifier(data.data.pkce);
			}
			oAuthWorker
				.initOPConfiguration()
				.then(() => {
					oAuthWorker
						.sendSignInRequest()
						.then((response: SignInResponse) => {
							if (response.type === SIGNED_IN) {
								port.postMessage({ success: true, data: { type: SIGNED_IN } });
							} else {
								port.postMessage({
									success: true,
									data: { type: AUTH_REQUIRED, code: response.code, pkce: response.pkce },
								});
							}
						})
						.catch((error) => {
							port.postMessage({ success: false, error: error });
						});
				})
				.catch((error) => {
					port.postMessage({ sucess: false, error: error });
				});
			break;
		case API_CALL:
			oAuthWorker
				.callAPI(data.data)
				.then((response) => {
					port.postMessage({ success: true, data: { ...response.data } });
				})
				.catch((error) => {
					port.postMessage({ success: false, error: error });
				});
			break;
		case LOGOUT:
			oAuthWorker
				.logout()
				.then((response) => {
					if (response) {
						port.postMessage({ success: true, data: true });
					} else {
						port.postMessage({ success: false, error: `Received ${response}` });
					}
				})
				.catch((error) => {
					port.postMessage({ success: false, error: error });
				});
			break;
		case SWITCH_ACCOUNTS:
			oAuthWorker
				.switchAccount(data.data)
				.then((response) => {
					if (response) {
						port.postMessage({ success: true, data: true });
					} else {
						port.postMessage({ success: false, error: `Received ${response}` });
					}
				})
				.catch((error) => {
					port.postMessage({ success: false, error: error });
				});
			break;
		default:
			port.postMessage({ success: false, error: `Unknown message type ${data?.type}` });
	}
};
