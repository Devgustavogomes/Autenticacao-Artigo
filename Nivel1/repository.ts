import { Injectable } from "@nestjs/common";
import { DatabaseService } from "src/infra/database/service";
import { findUserOutput } from "./constract";

@Injectable()
export class AuthRepository {
  constructor(private readonly databaseService: DatabaseService) {}

  async findUser(email: string): Promise<findUserOutput> {
    const sql = `SELECT 
                ID_USER,
                USERNAME,
                PASSWORD_HASH,
                ROLE
                FROM users
                WHERE email = $1`;
    const params = [email];
    const producer = await this.databaseService.query<findUserOutput>(
      sql,
      params,
    );

    return producer[0];
  }
}
