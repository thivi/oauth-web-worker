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

import { Message, ResponseMessage, SignInResponse, AuthCode } from "./models/message";
// @ts-ignore
import WorkerFile from "./oauth.worker.ts";
import { ConfigInterface } from "./models/client";
import { INIT, SIGN_IN, SIGNED_IN, AUTH_CODE, LOGOUT, SWITCH_ACCOUNTS, API_CALL, AUTH_REQUIRED } from "./constants";
import { AUTHORIZATION_CODE, PKCE_CODE_VERIFIER } from "./constants/token";
import { AccountSwitchRequestParams } from "./models";
import { AxiosRequestConfig, AxiosResponse } from "axios";

export class OAuth {
	private worker: Worker;
	private static instance: OAuth;
	private tab: Window;
	private initialized: boolean = false;
	private signedIn: boolean = false;

	private constructor() {
		this.worker = new WorkerFile();
	}

	public static getInstance() {
		if (this.instance) {
			return this.instance;
		} else {
			this.instance = new OAuth();
			return this.instance;
		}
	}

	public listenForAuthCode(): Promise<boolean> {
		if (!this.initialized) {
			return Promise.reject("The object has not been initialized yet.")
		}
		if (this.hasAuthorizationCode()) {
			const authCode = this.getAuthorizationCode();
			const message: Message<AuthCode> = {
				type: AUTH_CODE,
				data: {
					code: authCode,
					pkce: sessionStorage.getItem(PKCE_CODE_VERIFIER),
				},
			};

			history.pushState({}, document.title, this.removeAuthorizationCode());

			sessionStorage.removeItem(PKCE_CODE_VERIFIER);

			return this.communicate<AuthCode, SignInResponse>(message)
				.then((response) => {
					if (response.type === SIGNED_IN) {
						this.signedIn = true;
						return Promise.resolve(true);
					}

					return Promise.reject(
						"Something went wrong during authentication. " +
							"Failed during signing in after getting the authorization code."
					);
				})
				.catch((error) => {
					return Promise.reject(error);
				});
		} else {
			return Promise.reject("No Authorization Code found.");
		}
	}

	public initialize(config: ConfigInterface): Promise<boolean> {
		if (config.authorizationType && typeof config.authorizationType !== "string") {
			return Promise.reject("The authorizationType must be a string");
		}
		if (!(config.baseUrls instanceof Array)) {
			return Promise.reject("baseUrls must be an array");
		}
		if (config.baseUrls.find((baseUrl) => typeof baseUrl !== "string")) {
			return Promise.reject("Array elements of baseUrls must all be string values");
		}
		if (typeof config.callbackURL !== "string") {
			return Promise.reject("The callbackURL must be a string");
		}
		if (typeof config.clientHost !== "string") {
			return Promise.reject("The clientHost must be a string");
		}
		if (typeof config.clientID !== "string") {
			return Promise.reject("The clientID must be a string");
		}
		if (config.clientSecret && typeof config.clientSecret !== "string") {
			return Promise.reject("The clientString must be a string");
		}
		if (config.consentDenied && typeof config.consentDenied !== "boolean") {
			return Promise.reject("consentDenied must be a boolean");
		}
		if (config.enablePKCE && typeof config.enablePKCE !== "boolean") {
			return Promise.reject("enablePKCE must be a boolean");
		}
		if (config.prompt && typeof config.prompt !== "string") {
			return Promise.reject("The prompt must be a string");
		}
		if (config.responseMode && typeof config.responseMode !== "string") {
			return Promise.reject("The responseMode must be a string");
		}
		if (config.responseMode && config.responseMode !== "form_post" && config.responseMode !== "query") {
			return Promise.reject("The responseMode is invalid");
		}
		if (config.scope && !(config.scope instanceof Array)) {
			return Promise.reject("scope must be an array");
		}
		if (config.scope && config.scope.find((aScope) => typeof aScope !== "string")) {
			return Promise.reject("Array elements of scope must all be string values");
		}
		if (typeof config.serverOrigin !== "string") {
			return Promise.reject("serverOrigin must be a string");
		}
		if (config.tenant && typeof config.tenant !== "string") {
			return Promise.reject("The tenant must be a string");
		}
		if (config.tenantPath && typeof config.tenantPath !== "string") {
			return Promise.reject("The tenantPath must be a string");
		}

		const message: Message<ConfigInterface> = {
			type: INIT,
			data: config,
		};

		return this.communicate<ConfigInterface, null>(message)
			.then((response) => {
				this.initialized = true;
				return Promise.resolve(true);
			})
			.catch((error) => {
				return Promise.reject(error);
			});
	}

	private getAuthorizationCode(): string {
		if (new URL(window.location.href).searchParams.get(AUTHORIZATION_CODE)) {
			return new URL(window.location.href).searchParams.get(AUTHORIZATION_CODE);
		}

		return null;
	}

	private removeAuthorizationCode(): string {
		const url = location.href;
		return url.replace(/\?code=.*$/, "");
	}

	private hasAuthorizationCode(): boolean {
		return !!this.getAuthorizationCode();
	}

	public signIn(): Promise<boolean> {
		if (this.initialized) {
			const message: Message<null> = {
				type: SIGN_IN,
				data: null,
			};

			return this.communicate<null, SignInResponse>(message)
				.then((response) => {
					if (response.type === SIGNED_IN) {
						this.signedIn = true;
						return Promise.resolve(true);
					} else if (response.type === AUTH_REQUIRED && response.code) {
						if (response.pkce) {
							sessionStorage.setItem(PKCE_CODE_VERIFIER, response.pkce);
						}

						location.href = response.code;
					} else {
						return Promise.reject("Something went wrong during authentication");
					}
				})
				.catch((error) => {
					return Promise.reject(error);
				});
		} else {
			return Promise.reject("The object has not been initialized yet.")
		}
	}

	public logout(): Promise<boolean> {
		if (!this.signedIn) {
			return Promise.reject("You have not signed in yet");
		}
		const message: Message<null> = {
			type: LOGOUT,
		};

		return this.communicate<null, boolean>(message)
			.then((response) => {
				this.signedIn = false;
				return Promise.resolve(response);
			})
			.catch((error) => {
				return Promise.reject(error);
			});
	}

	public switchAccounts(requestParams: AccountSwitchRequestParams): Promise<boolean> {
		if (!this.initialized) {
			return Promise.reject("The object has not been initialzied yet")
		}

		if (!this.signedIn) {
			return Promise.reject("You have not signed in yet")
		}

		const message: Message<AccountSwitchRequestParams> = {
			type: SWITCH_ACCOUNTS,
			data: requestParams,
		};

		return this.communicate<AccountSwitchRequestParams, boolean>(message)
			.then((response) => {
				return Promise.resolve(response);
			})
			.catch((error) => {
				return Promise.reject(error);
			});
	}

	private communicate<T, R>(message: Message<T>, timeout?: number): Promise<R> {
		const channel = new MessageChannel();

		this.worker.postMessage(message, [channel.port2]);

		return new Promise((resolve, reject) => {
			const timer = setTimeout(() => {
				reject("Operation timed out");
			}, timeout ?? 5000);

			return (channel.port1.onmessage = ({ data }: { data: ResponseMessage<R> }) => {
				clearTimeout(timer);
				data.success ? resolve(data.data) : reject(data.error);
			});
		});
	}

	public httpRequest(config: AxiosRequestConfig): Promise<AxiosResponse> {
		if (!this.initialized) {
			return Promise.reject("The object has not been initialized yet ")
		}
		if (!this.signedIn) {
			return Promise.reject("You have not signed in yet")
		}
		const message: Message<AxiosRequestConfig> = {
			type: API_CALL,
			data: config,
		};
		return this.communicate<AxiosRequestConfig, AxiosResponse>(message)
			.then((response) => {
				return Promise.resolve(response);
			})
			.catch((error) => {
				return Promise.reject(error);
			});
	}
}
