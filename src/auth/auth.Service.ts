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
import { nanoid } from 'zod';
import { ResetOTP } from './schema/resetOTP.schema';
import { MailService } from 'src/services/mail.service';
import { randomInt } from 'crypto';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name)
    private readonly userModel: Model<User>,
    @InjectModel(RefreshToken.name)
    private readonly refreshTokenModel: Model<RefreshToken>,
    @InjectModel(ResetOTP.name)
    private readonly resetOTPModel: Model<ResetOTP>,
    private readonly jwtService: JwtService,
    private readonly mailService: MailService,
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

    const tokens = await this.generateTokens(user._id.toString(), user.role);
    return {
      ...tokens,
      userId: user._id,
    };
  }

  async generateTokens(userId: string, role: string) {
    const accessToken = await this.jwtService.signAsync(
      { userId, role },
      { expiresIn: '15m' },
    );
    const refreshToken = await this.jwtService.signAsync(
      { userId, role },
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

    const user = await this.userModel.findById(storedRefreashToken.userId);
    if (!user) {
      throw new UnauthorizedException();
    }

    return this.generateTokens(storedRefreashToken.userId, user.role);
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

  async forgotPassword(email: string) {
    const user = await this.userModel.findOne({ email: email });
    if (!user) {
      throw new BadRequestException('User not found');
    }
    const OTP = randomInt(100000, 999999).toString();
    const expiryDate = new Date(Date.now() + 3600 * 1000);
    const resetOTP = new this.resetOTPModel({
      userId: user._id,
      OTP: OTP,
      expiryDate: expiryDate,
    });
    await resetOTP.save();
    await this.mailService.sendPasswordResetEmail(email, OTP);
    return { message: 'Password reset OTP sent to your email' };
  }

  async resetPassword(newPassword: string, OTP: string) {
    const OTPEntry = await this.resetOTPModel.findOne({
      OTP: OTP,
      expiryDate: { $gt: new Date() },
    });
    if (!OTPEntry) {
      throw new BadRequestException('Invalid or expired OTP');
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await this.userModel.updateOne(
      { _id: OTPEntry.userId },
      { $set: { password: hashedPassword } },
    );

    await this.resetOTPModel.deleteOne({ _id: OTPEntry._id });

    return { message: 'Password has been reset successfully' };
  }

  async validateToken(token: string) {
    try {
      const payload = await this.jwtService.verifyAsync(token);
      const user = await this.userModel
        .findById(payload.userId)
        .select('-password');
      if (!user) {
        throw new UnauthorizedException('Invalid token : User not found');
      }
      return { valid: true, user };
    } catch {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  async getMe(userId: string) {
    if (!userId) throw new BadRequestException('User ID is required');
    const user = await this.userModel.findById(userId).select('-password');
    if (!user) throw new BadRequestException('User not found');
    return user;
  }

  async getmeThroughToken(token: string) {
    if (!token) throw new BadRequestException('Token is required');
    const payload = await this.jwtService.verifyAsync(token);
    const user = await this.userModel
      .findById(payload.userId)
      .select('-password');
    if (!user) throw new BadRequestException('User not found');
    return user;
  }

  async getAllBusinesses() {
    return this.userModel.find({ role: 'BUSINESS' }).select('-password');
  }

  async getAllBusinessesNotActivated() {
    return this.userModel
      .find({ role: 'BUSINESS', isActive: false })
      .select('-password');
  }

  async getOneUser(userId: string) {
    return this.userModel.findById(userId).select('-password');
  }

  async verifyBusiness(userId: string) {
    const user = await this.userModel.findById(userId);
    if (!user) {
      throw new BadRequestException('user not found');
    }
    if (user.isActive === false) {
      user.isActive = true;
    } else {
      user.isActive = false;
    }

    await user.save();
    return { message: 'verified successfully' };
  }

  async getAllOrganizers() {
    return this.userModel.find({ role: 'ORGANIZER' }).select('-password');
  }

  async getAllOrganizersNotActivated() {
    return this.userModel
      .find({ role: 'ORGANIZER', isActive: false })
      .select('-password');
  }
}
