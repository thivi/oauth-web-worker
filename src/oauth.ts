import { Message, ResponseMessage, SignInResponse } from "./models/message";
// @ts-ignore
import WorkerFile from "./oauth.worker.ts";
import { ConfigInterface } from "./models/client";
import { INIT, SIGN_IN, SIGNED_IN, AUTH_CODE, LOGOUT, SWITCH_ACCOUNTS, API_CALL } from "./constants";
import { AUTHORIZATION_CODE } from "./constants/token";
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

	public listenForAuthCode() {
		if (this.hasAuthorizationCode()) {
			const authCode = this.getAuthorizationCode();
			opener.postMessage(authCode);
			close();
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
		const message: Message<null> = {
			type: SIGN_IN,
			data: null,
		};

		return new Promise((resolve, reject) => {
			this.communicate<null, SignInResponse>(message)
				.then((response) => {
					if (response.type === SIGNED_IN) {
						resolve(true);
					} else if (response.code) {
						this.tab = open(response.code, "_blank");
						onmessage = (event: MessageEvent) => {
							if (event.origin === location.origin) {
								const authCode = event.data;
								const message: Message<string> = {
									type: AUTH_CODE,
									data: authCode,
								};

								return this.communicate<string, SignInResponse>(message)
									.then((response) => {
										if (response.type === SIGNED_IN) {
											resolve(true);
										}

										reject(
											"Something went wrong during authentication. " +
												"Failed during signing in after getting the authorization code."
										);
									})
									.catch((error) => {
										reject(error);
									});
							} else {
								reject("Origin mismatch");
							}
						};
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
