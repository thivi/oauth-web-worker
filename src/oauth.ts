import { Message, ResponseMessage, SignInResponse, AuthCode } from "./models/message";
// @ts-ignore
import WorkerFile from "./oauth.worker.ts";
import { ConfigInterface } from "./models/client";
import { INIT, SIGN_IN, SIGNED_IN, AUTH_CODE, LOGOUT, SWITCH_ACCOUNTS, API_CALL } from "./constants";
import { AUTHORIZATION_CODE, PKCE_CODE_VERIFIER } from "./constants/token";
import { AccountSwitchRequestParams } from "./models";
import { AxiosRequestConfig, AxiosResponse } from "axios";

export class OAuth {
	private worker: Worker;
	private static instance: OAuth;
	private tab: Window;

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
		if (this.hasAuthorizationCode()) {
			const authCode = this.getAuthorizationCode();
			const message: Message<AuthCode> = {
				type: AUTH_CODE,
				data: {
					code: authCode,
					pkce: sessionStorage.getItem(PKCE_CODE_VERIFIER),
				},
			};

			sessionStorage.removeItem(PKCE_CODE_VERIFIER);

			return this.communicate<AuthCode, SignInResponse>(message)
				.then((response) => {
					if (response.type === SIGNED_IN) {
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
		const message: Message<ConfigInterface> = {
			type: INIT,
			data: config,
		};

		return this.communicate<ConfigInterface, null>(message)
			.then((response) => {
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

	private hasAuthorizationCode(): boolean {
		return !!this.getAuthorizationCode();
	}

	public signIn(): Promise<boolean> {
		return new Promise((resolve, reject) => {
			const message: Message<null> = {
				type: SIGN_IN,
				data: null,
			};

			this.communicate<null, SignInResponse>(message)
				.then((response) => {
					if (response.type === SIGNED_IN) {
						resolve(true);
					} else if (response.code) {
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
		});
	}

	public logout(): Promise<boolean> {
		const message: Message<null> = {
			type: LOGOUT,
		};

		return this.communicate<null, boolean>(message)
			.then((response) => {
				return Promise.resolve(response);
			})
			.catch((error) => {
				return Promise.reject(error);
			});
	}

	public switchAccounts(requestParams: AccountSwitchRequestParams): Promise<boolean> {
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
