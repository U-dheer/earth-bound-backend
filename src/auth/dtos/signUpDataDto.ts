import {
  IsEmail,
  IsString,
  IsOptional,
  MinLength,
  IsIn,
  IsNumber,
  Matches,
} from 'class-validator';
import { RolesEnum } from '../utils/rolesEnum';
import { Transform } from 'class-transformer';

export class signUpDataDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(6)
  password: string;
  @IsString()
  @MinLength(6)
  passwordConfirm: string;

  @IsString()
  name: string;

  @Transform(({ value }) => value?.toUpperCase())
  @IsIn(['USER', 'ADMIN', 'ORGANIZER', 'BUSINESS'])
  role: RolesEnum;

  @IsOptional()
  @IsString()
  bussinessName?: string;

  @IsOptional()
  @IsString()
  bussinessAddress?: string;

  @IsOptional()
  @IsString()
  bussinessContact?: string;

  @IsOptional()
  @IsString()
  bussinessDescription?: string;

  @IsOptional()
  @IsString()
  accountNumber?: string;
}
