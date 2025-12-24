import {
  Body,
  Controller,
  Get,
  Param,
  Post,
  Put,
  UseGuards,
} from '@nestjs/common';
import { signUpDataDto } from './dtos/signUpDataDto';
import { AuthService } from './auth.Service';
import { loginDataDto } from './dtos/loginDataDto';
import { RefreshTokenDto } from './dtos/refreshTokenDto';
import { ChangePasswordto } from './dtos/changePassword.dto';
import { RequestUser } from 'src/decorators/request-user.decorator';
import { AuthGuard } from 'src/guards/auth.guard';
import { forgotPasswordDto } from './dtos/fogotPassword.dto';
import { ResetPasswordDto } from './dtos/resetPassword.dto';
import { VerifyBussinessDto } from './dtos/verifyBussiness.dto';
import { Roles } from 'src/decorators/roles.decorator';
import { RolesEnum } from './utils/rolesEnum';
import { RolesGuard } from 'src/guards/roles.guard';

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
    console.log('Fetching details for userId:', userId);
    return this.authService.getMe(userId);
  }

  @UseGuards(AuthGuard, RolesGuard)
  @Roles(RolesEnum.ADMIN)
  @Get('getAllBusinesses')
  async getAllBusinesses() {
    return this.authService.getAllBusinesses();
  }

  @UseGuards(AuthGuard, RolesGuard)
  @Roles(RolesEnum.ADMIN)
  @Get('getAllBusinesses-notActivated')
  async getAllBusinessesNotActivated() {
    return this.authService.getAllBusinessesNotActivated();
  }

  @UseGuards(AuthGuard, RolesGuard)
  @Roles(RolesEnum.ADMIN)
  @Get('getOneUser/:userId')
  async getOneUser(@Param('userId') userId: string) {
    return this.authService.getOneUser(userId);
  }

  @UseGuards(AuthGuard, RolesGuard)
  @Roles(RolesEnum.ADMIN)
  @Post('verify-users/:userId')
  async verifyBussiness(@Param('userId') userId: string) {
    return this.authService.verifyBusiness(userId);
  }

  @UseGuards(AuthGuard, RolesGuard)
  @Roles(RolesEnum.ADMIN)
  @Get('getAllOrganizers')
  async getAllOrganizers() {
    return this.authService.getAllOrganizers();
  }

  @UseGuards(AuthGuard, RolesGuard)
  @Roles(RolesEnum.ADMIN)
  @Get('getAllOrganizers-notActivated')
  async getAllOrganizersNotActivated() {
    return this.authService.getAllOrganizersNotActivated();
  }
}
