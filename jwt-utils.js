const { createHmac} = require("crypto");

function base64url(source) {
    const encoded=  Buffer.from(JSON.stringify(source)).toString('base64');
    const encoded_source = encoded.replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
    return encoded_source;
}
const signJWT = (payload, secret, expiresInSeconds = 3600) => {
    const header = {
        "alg": "HS256",
        "typ": "JWT"
    };
    const current_time = Math.floor(Date.now() / 1000);
    const exp = current_time + expiresInSeconds;
    const payload_withTime = { ...payload, exp};
    const encoded_header = base64url(header);
    const encoded_payload = base64url(payload_withTime);
    const signature = `${encoded_header}.${encoded_payload}`;
    const out_signature = createHmac('sha256', secret).update(signature).digest('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
    return `${encoded_header}.${encoded_payload}.${out_signature}`;
}

const verifyJWT = (token, secret) => {
    const [header, payload, signature] = token.split(".");
    const sign = `${header}.${payload}`;
    const out_signature = createHmac('sha256', secret).update(sign).digest('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
    if (out_signature === signature) {
        return "Invalid signature";
    }
    const payloadbase64 = payload.replace(/-/g, '+').replace(/_/g, '/').padEnd(payload.length + (4 - (payload.length % 4)) % 4, '=');
    try {
        const payloadJSON = Buffer.from(payloadbase64, 'base64').toString('utf-8');
        const orig_payload = JSON.parse(payloadJSON);
        if (Date.now() >= orig_payload.exp * 1000) {
            return "Token is expired";
        }
        return orig_payload;
    } catch (err) {
        console.error("invalid payload", err);
        return "Invalid Payload";
    }
}


// const token = signJWT({id: 123}, 'secret_key');
// console.log(token)
// console.log(verifyJWT(token, "secret_key"));

module.exports = { signJWT, verifyJWT };