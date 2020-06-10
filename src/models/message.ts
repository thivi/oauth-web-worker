import { INIT, SIGN_IN, SIGNED_IN, AUTH_REQUIRED, AUTH_CODE, LOGOUT, SWITCH_ACCOUNTS, API_CALL } from "../constants";

export interface ResponseMessage<T> {
	success: boolean;
	error?: string;
	data?: T;
}

export interface Message<T> {
	type: MessageType;
	data?: T;
}

export interface SignInResponse {
	type: typeof SIGNED_IN | typeof AUTH_REQUIRED;
	code?: string;
	pkce?: string;
}

export interface AuthCode{
	code: string;
	pkce?: string;
}

export type MessageType =
	| typeof INIT
	| typeof SIGN_IN
	| typeof AUTH_CODE
	| typeof LOGOUT
	| typeof SWITCH_ACCOUNTS
	| typeof API_CALL;
