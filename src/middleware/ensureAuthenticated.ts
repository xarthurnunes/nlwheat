import { Request, Response, NextFunction } from 'express';
import { verify } from 'jsonwebtoken';

interface IPayload {
    sub: string;
}

export function ensureAuthenticated(request: Request, response: Response, next: NextFunction) {
    const authToken = request.headers.authorization;

    if(!authToken) {
        response.status(401).json({
            errorCode: "token.invalid",
        });
    }

    //Bearer 09128390128390128
    // [0] = Bearer
    // [1] = 09128390128390128

    const [, token] = authToken.split(' ');

    try {
    const { sub } = verify(token, process.env.JWT_SECRET) as IPayload;
    
    request.user_id = sub;

    return next();
    } catch(err) {  
        return response.status(401).json({ errorCode: "token.expired" });
    }

}