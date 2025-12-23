import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { RolesEnum } from '../utils/rolesEnum';

@Schema()
export class User extends Document {
  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: true })
  password: string;

  @Prop()
  name: string;

  @Prop({ type: String, enum: RolesEnum, default: RolesEnum.USER })
  role: RolesEnum;

  @Prop()
  isActive: boolean;

  @Prop()
  bussinessName: string;

  @Prop()
  bussinessAddress: string;

  @Prop()
  bussinessContact: string;

  @Prop()
  bussinessDescription: string;

  @Prop({ default: 0 })
  redeemPoints: number;

  @Prop()
  accountNumber: string;
}

export const UserSchema = SchemaFactory.createForClass(User);

// Add pre-save hook to handle isActive logic
UserSchema.pre('save', function (next) {
  if (this.isNew) {
    if (this.role === RolesEnum.BUSINESS || this.role === RolesEnum.ORGANIZER) {
      this.isActive = false;
    } else {
      this.isActive = true;
    }
  }
  next();
});
