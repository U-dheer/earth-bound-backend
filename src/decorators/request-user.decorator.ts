import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const RequestUser = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    // Check what property your JWT payload uses
    return request.user?.sub || request.user?.userId || request.user?.id;
  },
);
