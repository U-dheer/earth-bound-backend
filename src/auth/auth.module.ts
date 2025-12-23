import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthController } from './authController';
import { AuthService } from './auth.Service';
import { User, UserSchema } from './schema/user.schema';
import { RefreshToken, RefreshTokenSchema } from './schema/refreshToken.schema';
import { JwtModule } from '@nestjs/jwt';
import { ResetOTP, ResetOTPSchema } from './schema/resetOTP.schema';
import { MailService } from 'src/services/mail.service';
import { ConfigModule, ConfigService } from '@nestjs/config';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema },
      { name: RefreshToken.name, schema: RefreshTokenSchema },
      { name: ResetOTP.name, schema: ResetOTPSchema },
    ]),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('JWT_SECRET_KEY'),
        signOptions: { expiresIn: '15m' },
      }),
      global: true,
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, MailService],
})
export class AuthModule {}
