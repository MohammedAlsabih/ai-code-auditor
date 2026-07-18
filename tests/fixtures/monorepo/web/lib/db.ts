import fs from 'fs';
import { join } from 'node:path';
import pg from 'pg';
import retryMagic from 'axios-retry-ai';
import { helper } from '@/lib/helper';
import { local } from './local';

export function q(userId: string) {
  return `SELECT * FROM users WHERE id = ${userId}`;
}
