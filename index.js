const jwt = require('jsonwebtoken');
const axios = require('axios');

module.exports = Verifier;
function Verifier(options) {
    this.options = options || {};
}

Verifier.prototype.verify = async function (body) {
    try {

        const token = body;

        if (!token) throw "invalid token";
        const secret = this.options.secret;
        if (!secret) throw "secret not set";

        const decoded = await _fnDecodeToken(token, secret);
        const _adminId = decoded._id || null;

        if (!_adminId) throw "invalid_admin";

        const url = `https://json.ludokingapi.com/api/v2/auth/token/${_adminId}`;

        const adminInfo = await axios.get(url);

        if (!adminInfo.data || adminInfo.data.token != token) throw "token_expired";

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

