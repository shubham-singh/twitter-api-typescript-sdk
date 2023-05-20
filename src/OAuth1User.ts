import crypto from 'crypto';
import { AuthClient, AuthHeader } from "./types";

export interface OAuth1UserOptions {
    /** oauth_consumer_key identifies which application is making the request. Obtain this value from the settings page for your Twitter app in the developer portal */
    oauth_consumer_key: string
    /** oauth_consumer_secret identifies as the password for the app which is making request */
    oauth_consumer_secret: string
    /**
     * You can generate your own access token and token secret if you would like your app to make requests on behalf of the same Twitter account associated with your developer account on the Twitter developer app's details page.
     */
    /** oauth_token parameter typically represents a user’s permission to share access to their account with your application */
    oauth_token: string
    /** oauth_token_secret identifies the account your application is acting on behalf of is called the OAuth token secret */
    oauth_token_secret: string
}

export interface OAuth1SignaturePayload {
    include_entities: true
    oauth_consumer_key: string
    oauth_nonce: string,
    oauth_signature_method: 'HMAC-SHA1',
    oauth_timestamp: string,
    oauth_token: string,
    oauth_version: '1.0',
    status: string
}

export class OAuth1User implements AuthClient {
    #options: OAuth1UserOptions;
    private oAuth1SignaturePayload: OAuth1SignaturePayload

    constructor(options: OAuth1UserOptions) {
        this.#options = options
        this.oAuth1SignaturePayload = {} as OAuth1SignaturePayload
        this.oAuth1SignaturePayload.oauth_consumer_key = options.oauth_consumer_key
        this.oAuth1SignaturePayload.oauth_token = options.oauth_token
    }

    encodeRFC3986URIComponent(str: string): string {
        return encodeURIComponent(str).replace(
            /[!'()*]/g,
            (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
        );
    }

    getNonce(): string {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let nonce = '';

        for (let i = 0; i < 32; i++) {
            const randomIndex = Math.floor(Math.random() * chars.length);
            nonce += chars.charAt(randomIndex);
        }

        return nonce;
    }

    getParameterString(nonce: string, timestamp: string): string {
        this.oAuth1SignaturePayload.oauth_nonce = nonce
        this.oAuth1SignaturePayload.oauth_timestamp = timestamp
        const parameterString =  Object.entries(this.oAuth1SignaturePayload).reduce((accumulator, current) => {
            accumulator += `&${current[0]}=${current[1]}`
            return accumulator
        }, '')
        return this.encodeRFC3986URIComponent(parameterString)
    }

    getSignatureBaseString(url: string, httpMethod: string, nonce: string, timestamp: string): string {
        const parameterString = this.getParameterString(nonce, timestamp)
        const prefix = httpMethod.toUpperCase() + '&' + this.encodeRFC3986URIComponent(url)
        return prefix + parameterString
    }

    getSigningKey(): string {
        const signingKey = this.#options.oauth_consumer_secret + this.#options.oauth_token_secret
        return this.encodeRFC3986URIComponent(signingKey)
    }

    getSignature(url: string, method: string, nonce: string, timestamp: string): string {
        const key = this.getSigningKey()
        const data = this.getSignatureBaseString(url, method, nonce, timestamp)
        const signature = crypto.createHmac('sha1', key).update(data).digest('base64')
        return signature
    }

    getAuthHeader(url: string, method: string): AuthHeader {
        const nonce = this.getNonce()
        const timestamp = String(Date.now())
        const oauth_signature = this.getSignature(url, method, nonce, timestamp)
        return {
            Authorization: `OAuth oauth_consumer_key="${this.#options.oauth_consumer_key}", oauth_nonce="${nonce}", oauth_signature="${oauth_signature}", oauth_signature_method="HMAC-SHA1", oauth_timestamp="${timestamp}", oauth_token="${this.#options.oauth_token}", oauth_version="1.0"`
        }
    }
}
