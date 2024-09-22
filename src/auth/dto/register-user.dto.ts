import { IsEmail, IsString, IsStrongPassword, Length } from "class-validator";

export class RegisterUserDto {
  @IsString()
  @Length(3, 255)
  name: string;

  @IsEmail()
  @IsString()
  email: string;

  @IsString()
  @IsStrongPassword()
  password: string;
}
