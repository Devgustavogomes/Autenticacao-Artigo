import {
  Body,
  Controller,
  Post,
  Get,
  UseGuards,
  HttpCode,
  HttpStatus,
} from "@nestjs/common";
import { loginInputDto } from "./dto";
import { AuthService } from "./service";
import type { AuthenticatedRequest } from "authenticatedRequest"; // só exemplo
import { AuthGuard } from "../Middleware";

@Controller("auth")
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post("login")
  @HttpCode(HttpStatus.OK)
  async login(@Body() data: loginInputDto) {
    return await this.authService.login(data);
  }

  @Get("logout")
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  async logout(@Req() req: AuthenticatedRequest) {
    await this.authService.logout(req.user);

    return { message: "Logout realizado com sucesso" };
  }
}
