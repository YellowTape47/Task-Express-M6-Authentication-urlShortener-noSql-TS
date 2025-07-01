import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

export function authorize(req: Request, res: Response, next: NextFunction) {
    const header = req.headers.authorization;
    console.log(header);
    if (!header) {
        res.status(401).json({ message: "No token provided" });
    }

    const [scheme, token] = header?.split(" ") || [];
    if (scheme !== "Bearer" || !token) {
        res.status(401).json({ message: "Invalid auth format" });
    }

    try {
        const payload = jwt.verify(token, "SecretKey");
        (req as any).user = payload;
        next();
    } catch (err) {
        res.status(401).json({ message: "Invalid or expired token" });
    }
}
