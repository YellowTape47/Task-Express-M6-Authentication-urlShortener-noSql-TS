import { NextFunction, Request, Response } from "express";
import User from "../../models/User";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

const SALT = 10;

const generateToken = (id: string, username: string) => {
    const token = jwt.sign({ userId: id, username }, process.env.API_KEY as string, { expiresIn: "1h" });
    return token;
};

export const signup = async (req: Request, res: Response, next: NextFunction) => {
    try {
        // extract username and password from req.body
        const { username, password } = req.body;

        // check if the user already exist
        const userExist = await User.findOne({ username });

        if (userExist) {
            res.status(401).json("userExisits");
        }

        res.status(201).json({ username, password });

        // hash the password
        const hashedPass = await bcrypt.hash(password, SALT);

        // store the hashed pass
        const user = await User.create({ username, hashedPass });

        // generate token
        const token = generateToken(`${user._id}`, user.username!);

        res.status(201).json({ token });
    } catch (error) {
        res.status(500).json({ message: "Something went wrong" });
    }
};

export const signin = async (req: Request, res: Response, next: NextFunction) => {
    try {
        // extract username and password from req.body
        const { username, password } = req.body;

        // verification
        const userExsist = await User.findOne({ username });
        if (!userExsist) {
            res.json("Not Authorized");
        }

        // compare hashed passwored
        const userMatch = await bcrypt.compare(password, userExsist?.password!);
        if (userMatch) {
            const token = generateToken(`${userExsist?._id}`, userExsist?.username!);
            res.status(200).json(token);
        } else {
            res.status(400).json("Not Authorized");
        }
    } catch (err) {
        next(err);
    }
};

export const getUsers = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const users = await User.find().populate("urls");
        res.status(201).json(users);
    } catch (err) {
        next(err);
    }
};
