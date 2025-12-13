import {
  BadRequestException,
  Body,
  Inject,
  Injectable,
  Post,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schema/user.schema';
import { Model } from 'mongoose';
import { RefreshToken } from './schema/refreshToken.schema';
import { signUpDataDto } from './dtos/signUpDataDto';
import * as bcrypt from 'bcrypt';
import { loginDataDto } from './dtos/loginDataDto';
import { JwtService } from '@nestjs/jwt';
import { RefreshTokenDto } from './dtos/refreshTokenDto';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name)
    private readonly userModel: Model<User>,
    @InjectModel(RefreshToken.name)
    private readonly refreshTokenModel: Model<RefreshToken>,
    private readonly jwtService: JwtService,
  ) {}

  async signUp(signUpData: signUpDataDto) {
    const exsitingUser = await this.userModel.findOne({
      email: signUpData.email,
    });
    if (exsitingUser) {
      throw new Error('User already exists');
    }

    if (signUpData.password !== signUpData.passwordConfirm) {
      throw new BadRequestException('Passwords are not identical');
    }

    let hashedPassword = await bcrypt.hash(signUpData.password, 10);

    await this.userModel.create({
      email: signUpData.email,
      password: hashedPassword,
      name: signUpData.name,
      role: signUpData.role,
      bussinessName: signUpData.bussinessName,
      bussinessAddress: signUpData.bussinessAddress,
      bussinessContact: signUpData.bussinessContact,
      bussinessDescription: signUpData.bussinessDescription,
      accountNumber: signUpData.accountNumber,
    });

    return { message: 'User created successfully' };
  }

  async login(loginData: loginDataDto) {
    const user = await this.userModel.findOne({ email: loginData.email });
    if (!user) {
      throw new BadRequestException('Invalid credentials');
    }

    const isCorrectPassword = await bcrypt.compare(
      loginData.password,
      user.password,
    );
    if (!isCorrectPassword) {
      throw new BadRequestException('Invalid credentials');
    }

    const tokens = await this.generateTokens(user._id.toString());
    return {
      ...tokens,
      userId: user._id,
    };
  }

  async generateTokens(userId: string) {
    const accessToken = await this.jwtService.signAsync(
      { userId },
      { expiresIn: '15m' },
    );
    const refreshToken = await this.jwtService.signAsync(
      { userId },
      { expiresIn: '7d' },
    );
    await this.storeRefreshToken(userId, refreshToken);
    return { accessToken, refreshToken };
  }

  async storeRefreshToken(userId: string, refreshToken: string) {
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 7); // 7 days validity

    await this.refreshTokenModel.updateOne(
      { userId },
      {
        $set: { expiryDate, refreshToken },
      },
      {
        upsert: true,
      },
    );
  }

  async refreshTokens(oldRefreshTokenDto: RefreshTokenDto) {
    const storedRefreashToken = await this.refreshTokenModel.findOne({
      refreshToken: oldRefreshTokenDto.refreshToken,
      expiryDate: { $gt: new Date() },
    });

    if (!storedRefreashToken) {
      throw new UnauthorizedException();
    }

    return this.generateTokens(storedRefreashToken.userId);
  }

  async changePassword(
    userId: string,
    oldPassword: string,
    newPassword: string,
  ) {
    console.log('Changing password for userId:', userId);
    const user = await this.userModel.findById(userId);
    if (!user) {
      throw new BadRequestException('User not found');
    }

    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      throw new BadRequestException('Old password is incorrect');
    }

    if (oldPassword === newPassword) {
      throw new BadRequestException('New password must be different');
    }

    const hashed = await bcrypt.hash(newPassword, 10);
    await this.userModel.updateOne(
      { _id: userId },
      { $set: { password: hashed } },
    );

    return { message: 'Password changed successfully' };
  }
}
