import { IsString } from 'class-validator';

export class VerifyBussinessDto {
  @IsString()
  businessId: string;
}
