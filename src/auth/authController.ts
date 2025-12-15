import { Body, Controller, Get, Post, Put, UseGuards } from '@nestjs/common';
import { signUpDataDto } from './dtos/signUpDataDto';
import { AuthService } from './authService';
import { loginDataDto } from './dtos/loginDataDto';
import { RefreshTokenDto } from './dtos/refreshTokenDto';
import { ChangePasswordto } from './dtos/changePassword.dto';
import { RequestUser } from 'src/decorators/request-user.decorator';
import { AuthGuard } from 'src/guards/auth.guard';
import { forgotPasswordDto } from './dtos/fogotPassword.dto';
import { ResetPasswordDto } from './dtos/resetPassword.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  async signUp(@Body() signUpData: signUpDataDto) {
    return this.authService.signUp(signUpData);
  }

  @Post('login')
  async login(@Body() loginData: loginDataDto) {
    return this.authService.login(loginData);
  }

  @Post('refresh')
  async refreshTokens(@Body() oldRefreshToken: RefreshTokenDto) {
    return this.authService.refreshTokens(oldRefreshToken);
  }

  @Put('change-password')
  @UseGuards(AuthGuard)
  async chnagePassword(
    @Body() changePasswordDto: ChangePasswordto,
    @RequestUser() userId: string,
  ) {
    return this.authService.changePassword(
      userId,
      changePasswordDto.oldPassword,
      changePasswordDto.newPassword,
    );
  }

  @Post('forgot-password')
  async forgotPassword(@Body() forgottenemail: forgotPasswordDto) {
    return this.authService.forgotPassword(forgottenemail.email);
  }

  @Post('reset-password')
  async resetPassword(@Body() resetPasswordData: ResetPasswordDto) {
    return this.authService.resetPassword(
      resetPasswordData.newPassword,
      resetPasswordData.otp,
    );
  }

  @Post('validate')
  async validateToken(@Body() tokenData: { token: string }) {
    return this.authService.validateToken(tokenData.token);
  }

  @Get('me')
  @UseGuards(AuthGuard)
  async me(@RequestUser() userId: string) {
    return this.authService.getMe(userId);
  }
}
