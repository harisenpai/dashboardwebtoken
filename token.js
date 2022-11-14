const jwt = require('jsonwebtoken');
const axios = require('axios');

const verifyToken = async (req, res, next) => {
    try {
        console.log("in token", req);
        const token = req.token;
        const secret = "secret";
        console.log(" token",token,"secret",secret);


        if (!token || !secret) throw "invalid_info";

        const decoded = await _fnDecodeToken(token, secret);
        const _adminId = decoded._id || null;
        if (!_adminId) throw "invalid_admin";

        const url = `https://json.ludokingapi.com/api/v2/auth/token/${_adminId}`;
        const adminInfo = await axios.get(url);

        if (!adminInfo.data || adminInfo.data.token != token) throw "token_expired";

        res.send(
            {
                isSuccess: 1,
                "_adminId": _adminId,
                "permissions": JSON.parse(adminInfo.data.permissions)
            }
        );
    }
    catch (err) {
        return err
    }
}

module.exports = {
    verifyToken
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