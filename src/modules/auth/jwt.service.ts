import jwt from 'jsonwebtoken'
import { JWT_SECRET_KEY } from '../../config/env.config';
import { Request, Response } from 'express';
import { IUserSesion, UserRole } from '../products/products.routes';

interface IAuthToken {
  name: string;
  email: string;
  uid: string;
  role: UserRole;
}

export function generateAccessToken(payload: IAuthToken): string {
  if (!JWT_SECRET_KEY) {
    throw new Error('JWT_SECRET_KEY is not defined');
  }

  return jwt.sign(
    payload,
    JWT_SECRET_KEY,
    {
      expiresIn: '1h',
      algorithm: 'HS256',
    }
  );
}

export const validateSesionUser = (req: Request, res: Response, next: any) => {
  // Middleware logic to validate user session
  const { authorization } = req.headers;

  console.log('authorization:', authorization);
  if (!authorization) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  // validar si el jwt es valido y no a expirado
  // "Bearer eyJhbGciOiJIUzI" => ['Bearer', 'eyJhbGciOiJIUzI']
  const token = authorization.split(' ')[1];

  console.log('token:', token);
  jwt.verify(
    token,
    JWT_SECRET_KEY ?? 'asdf',
    (err, decoded) => {
    if (err) {
      console.error('Error validating JWT:', err);
      return res.status(401).json({ message: 'Unauthorized' });
    }

    console.log('User session validated:', decoded);
    req.user = decoded as IUserSesion;

    console.log('user session validated:', req.user);
    next();
  });
};

export const userRoleValidation = (role: UserRole) => {
  return (req: Request, res: Response, next: any) => {
    const user = req.user;

    console.log('user role validation', user,  role);
    if (!user || !user.role) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    if (user.role !== role) {
      return res.status(403).json({ message: 'Forbidden' });
    }
  
    next();
  }
};
