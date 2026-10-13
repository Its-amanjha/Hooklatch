import type { ContextVariableMap } from 'hono';
import type { WebhookVariables } from '../../src/adapters/hono.js';

type Expect<T extends true> = T;
// Importing the adapter must not promise verification on unrelated Hono routes.
type UnverifiedContextIsOptional = Expect<undefined extends ContextVariableMap['webhook'] ? true : false>;
// Explicitly typed middleware scopes retain the ergonomic nonnullable result.
type VerifiedContextIsRequired = Expect<undefined extends WebhookVariables['webhook'] ? false : true>;
export type { UnverifiedContextIsOptional, VerifiedContextIsRequired };
