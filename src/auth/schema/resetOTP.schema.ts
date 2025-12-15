import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';

@Schema({ versionKey: false, timestamps: true })
export class ResetOTP extends Document {
  @Prop({ required: true })
  OTP: string;

  @Prop({ required: true, type: mongoose.Types.ObjectId })
  userId: mongoose.Types.ObjectId;

  @Prop({ type: Date, required: true, expires: 3600 })
  expiryDate: Date;
}

export const ResetOTPSchema = SchemaFactory.createForClass(ResetOTP);
