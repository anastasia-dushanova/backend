const jwt = require("jsonwebtoken");

const signatureAccess = "secret access";
const signatureRefresh = "secret refresh";

const accessTokenAge = 20;
const refreshTokenAge = 60*60;

const verifyAuthorizationMiddleware = (req, res, next) =>{
    const token = req.headers.authorization 
    ? req.headers.authorization.split(" ")[1]
    : "";

    if(!token){
        return res.sendStatus(401);
    }

    try{
        const decoded = jwt.verify(token, signatureAccess);
        req.user = decoded;
    }catch(err){
        return res.sendStatus(401);
    }
    return next();
};

const verifyRefreshTokenMiddleware = (req, res, next) => {
    const refreshToken = req.cookies.refreshToken;

    if(!refreshToken){
        return res.sendStatus(401);
    }

    try{
        const decoded = jwt.verify(refreshToken, signatureRefresh);
        req.user = decoded;
    }catch(err){
        return res.sendStatus(401);
    }
    return next();
};

const getTokens = (login) => ({
    accessToken: jwt.sign({login}, signatureAccess, {
        expiresIn: `${accessTokenAge}s`,
    }),
    refreshToken: jwt.sign({login}, signatureRefresh, {
        expiresIn: `${refreshTokenAge}s`,
    }),
});

module.exports = {
    getTokens,
    refreshTokenAge,
    verifyAuthorizationMiddleware,
    verifyRefreshTokenMiddleware
};