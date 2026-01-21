import { JwtService } from "@nestjs/jwt";
import { Injectable, UnauthorizedException } from "@nestjs/common";
import { loginInputDto } from "./dto";
import { compare } from "bcryptjs";
import { AuthenticatedRequest } from "src/shared/types/authenticatedRequest";
import { ConfigService } from "@nestjs/config";
import { AuthContract } from "./constract";
@Injectable()
export class AuthService {
  constructor(
    private readonly authRepository: AuthContract,
    private readonly jwtService: JwtService,
  ) {}

  async login(data: loginInputDto): Promise<string> {
    const user = await this.authRepository.findUser(data.email);

    if (!user) {
      throw new NotFoundException("User not found");
    }

    const isMatch = await compare(data.password, user.password_hash);

    if (!isMatch) {
      throw new UnauthorizedException("Invalid credentials");
    }

    try {
      const payload = {
        id: user.id_user,
        username: user.username,
        role: user.role,
      };

      return await this.jwtService.signAsync(payload);
    } catch {
      throw new UnauthorizedException();
    }
  }
}
