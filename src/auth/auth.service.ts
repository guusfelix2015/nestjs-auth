import { Injectable } from '@nestjs/common';

@Injectable()
export class AuthService {
  constructor() {}

  async signnup() {
    return { message: 'signup was succefull' };
  }

  async signin() {
    return '';
  }

  async signout() {
    return '';
  }
}
