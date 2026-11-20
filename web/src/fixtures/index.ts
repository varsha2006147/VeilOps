import type { ApiResponses } from '../types';
import { live } from './live';
import { incidents } from './incidents';
import { summary } from './summary';
import { about } from './about';
import { today } from './today';
import { fleet } from './fleet';
import { ledger } from './ledger';

export const fixtures: ApiResponses = {
  '/summary/today': today,
  '/fleet': fleet,
  '/ledger?limit=6': ledger,
  '/live': live,
  '/incidents': incidents,
  '/summary': summary,
  '/about': about,
};
