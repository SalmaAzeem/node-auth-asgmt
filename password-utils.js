const { pbkdf2Sync, randomBytes, hash } = require("crypto");

const hashPassword = (password) => {
    const salt = randomBytes(16).toString("hex");
    const hash = pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString("hex");
    const hashed_password = `${salt}:${hash}`
    return hashed_password;
};

const verifyPassword = (password, storedHash) => {
    const [salt, pass] = storedHash.split(":");
    const hashed_pass = pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString("hex");
    return hashed_pass === pass;
}

// const hashed = hashPassword("salma123");
// console.log(verifyPassword("salma123", hashed));

module.exports = { hashPassword, verifyPassword };