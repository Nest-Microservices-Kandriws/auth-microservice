import { HttpStatus, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { LoginUserDto, RegisterUserDto } from './dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
    private readonly logger = new Logger(AuthService.name);

    constructor(private jwtService: JwtService) {
        super();
    }
    onModuleInit() {
        this.$connect();
        this.logger.log('MongoDB initialized');
    }

    async signJWT(payload: JwtPayload) {
        return this.jwtService.sign(payload);
    }

    async registerUser(registerUserDto: RegisterUserDto) {
        const { email, name, password } = registerUserDto;
        try {
            const user = await this.user.findUnique({
                where: {
                    email
                }
            });

            if (user) {
                throw new RpcException({
                    message: 'User already exists',
                    status: HttpStatus.BAD_REQUEST
                });
            }

            const newUser = await this.user.create({
                data: {
                    email,
                    name,
                    password: bcrypt.hashSync(password, 10)
                }
            });

            const { password: __, ...rest } = newUser;
            const token = await this.signJWT(rest);
            return {
                user: rest,
                token
            };
        } catch (error) {
            throw new RpcException({
                message: error.message,
                status: HttpStatus.BAD_REQUEST
            });
        }


    }
    async loginUser(loginUserDto: LoginUserDto) {
        const { email, password } = loginUserDto;
        try {
            const user = await this.user.findUnique({
                where: { email }
            });

            if (!user) {
                throw new RpcException({
                    message: 'Invalid credentials',
                    status: HttpStatus.BAD_REQUEST
                });
            }

            const isPasswordValid = bcrypt.compareSync(password, user.password);

            if (!isPasswordValid) {
                throw new RpcException({
                    message: 'Invalid credentials',
                    status: HttpStatus.BAD_REQUEST
                });
            }

            const { password: __, ...rest } = user;
            const token = await this.signJWT(rest);
            return {
                user: rest,
                token
            };
        } catch (error) {
            throw new RpcException({
                message: error.message,
                status: HttpStatus.BAD_REQUEST
            });
        }

    }

    async verifyUser(token: string) {
        try {

            const { sub, iat, exp, ...user } = await this.jwtService.verify(token, {
                secret: envs.JWT_SECRET
            });

            const reToken = await this.signJWT(user);

            return {
                user: user,
                token: reToken
            };
        } catch (error) {
            throw new RpcException({
                message: 'Invalid token',
                status: HttpStatus.UNAUTHORIZED
            });
        }
    }

}
