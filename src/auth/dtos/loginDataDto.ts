import { IsString } from 'class-validator';

export class loginDataDto {
  @IsString()
  email: string;

  @IsString()
  password: string;
}
