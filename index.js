const axios = require('axios');
const CryptoJS = require('crypto-js');
const url = require('url');

const OAUTH_NONCE = Math.random().toString(36).replace(/[^\w]/g, '');
const OAUTH_SIGNATURE_METHOD = 'HMAC-SHA1';
const OAUTH_TIMESTAMP = parseInt(Date.now() / 1000);
const OAUTH_VERSION = '1.0';

const VERSION = '1.1';
const BASE_URL = `https://api.twitter.com/${VERSION}`;

class Twitter {
    accessSecret = null;
    apiSecret = null;
    lowestId = null;
    parameters = {
        oauth_consumer_key: null,
        oauth_token: null,

        oauth_nonce: null,
        oauth_signature_method: null,
        oauth_timestamp: null,
        oauth_version: null
    };

    constructor(data) {
        this._validateConstructor(data);

        this.accessSecret = data.accessSecret;
        this.apiSecret = data.apiSecret;
        this.parameters.oauth_consumer_key = data.consumerKey;
        this.parameters.oauth_token = data.accessToken;

        this.parameters.oauth_nonce = OAUTH_NONCE;
        this.parameters.oauth_signature_method = OAUTH_SIGNATURE_METHOD;
        this.parameters.oauth_timestamp = OAUTH_TIMESTAMP;
        this.parameters.oauth_version = OAUTH_VERSION;
    }

    createTweet(params) {
        const statusUrl = `${BASE_URL}/statuses/update.json`;
        params.status = params.status.replace(/\*/g, '-');
        const authorization = this._getAuthorizationHeader('post', statusUrl, params);
        const urlParams = new url.URLSearchParams(params);
        return axios.post(statusUrl, urlParams, {
            headers: {
                authorization: authorization,
            }
        });
    }

    getTimeline(params) {
        if (params.max_id == null)
            delete params.max_id;

        const timelineUrl = `${BASE_URL}/statuses/user_timeline.json`;
        const authorization = this._getAuthorizationHeader('get', timelineUrl, params);
        return axios.get(timelineUrl, {
            headers: {
                authorization: authorization
            },
            params: params
        });
    }

    _createSignature(method, baseUrl, parameters) {
        let encodedParameters = '';
        Object.keys(parameters).sort().forEach(key => {
            encodedParameters += `${encodeURIComponent(key)}=${encodeURIComponent(parameters[key])}&`;
            encodedParameters = encodedParameters.replace(/!/g, '%21');
            encodedParameters = encodedParameters.replace(/\'/g, '%27');
            // TODO: Figure out issue with asterisks, node, and twitter api
            //encodedParameters = encodedParameters.replace(/\*/g, '%2A');
            encodedParameters = encodedParameters.replace(/\(/g, '%28').replace(/\)/g, '%29');
        });
        if (encodedParameters.length) encodedParameters = encodedParameters.substr(0, encodedParameters.length - 1);

        const signatureBaseString = `${method.toUpperCase()}&${encodeURIComponent(baseUrl)}&${encodeURIComponent(encodedParameters)}`;
        const signingKey = `${encodeURIComponent(this.apiSecret)}&${encodeURIComponent(this.accessSecret || '')}`;

        return CryptoJS.HmacSHA1(signatureBaseString, signingKey).toString(CryptoJS.enc.Base64);
    }

    _getAuthorizationHeader(method, baseUrl, params) {
        const signature = this._createSignature(method, baseUrl, Object.assign({}, params, this.parameters));
        return `OAuth oauth_consumer_key="${encodeURIComponent(this.parameters.oauth_consumer_key)}", oauth_nonce="${encodeURIComponent(this.parameters.oauth_nonce)}", oauth_signature="${encodeURIComponent(signature)}", oauth_signature_method="${encodeURIComponent(this.parameters.oauth_signature_method)}", oauth_timestamp="${encodeURIComponent(this.parameters.oauth_timestamp)}", oauth_token="${encodeURIComponent(this.parameters.oauth_token)}", oauth_version="${encodeURIComponent(this.parameters.oauth_version)}"`;
    }

    _validateConstructor(data) {
        if (data == null)
            throw 'Missing data param';
        if (data.accessSecret == null)
            throw 'Missing accessSecret in constructor data';
        if (data.accessToken == null)
            throw 'Missing accessToken in constructor data';
        if (data.apiSecret == null)
            throw 'Missing apiSecret in constructor data';
        if (data.consumerKey == null)
            throw 'Missing consumerKey in constructor data';
    }
}

module.exports = Twitter;
