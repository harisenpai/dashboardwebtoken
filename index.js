const jwt = require('jsonwebtoken');
const axios = require('axios');

module.exports = Verifier;
function Verifier(options) {
    this.options = options || {};
}

Verifier.prototype.verify = async function (body) {
    try {
        const token = body;
        if (!token) {
            const err = new Error('Token is required');
            err.data = 'token is required';
            err.status = 412;
            throw err;
        }

        const secret = this.options.secret;
        if (!secret) {
            const err = new Error('Secret is required');
            err.data = 'Secret is required';
            err.status = 412;
            throw err;
        }

        const decoded = await _fnDecodeToken(token, secret);
        const _adminId = decoded._id || null;
        if (!_adminId)  {
            const err = new Error('Invalid admin');
            err.data = 'Invalid admin';
            err.status = 401;
            throw err;
        }

        const url = `https://json.ludokingapi.com/api/v2/auth/token/${_adminId}`;
        const adminInfo = await axios.get(url);
        if (!adminInfo.data || adminInfo.data.token != token)  {
            const err = new Error('token expired');
            err.data = 'token expired';
            err.status = 401;
            throw err;
        }

        return (
            {
                isSuccess: 1,
                "_adminId": _adminId,
                "permissions": JSON.parse(adminInfo.data.permissions)
            }
        );
    }
    catch (err) {
        throw err
    }
}

const _fnDecodeToken = async (token, secret) => {
    try {
        return jwt.verify(token, secret);
    } catch (err) {
        const tokenError = new Error('Authentication Error');
        tokenError.data = 'authentication_error';
        tokenError.status = 401;
        throw tokenError;
    }
};

