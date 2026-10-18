export interface IdentifiedEvent {
  readonly id: string;
}

export interface StripeEvent extends IdentifiedEvent {
  readonly type: string;
}

export function isIdentifiedEvent(value: unknown): value is IdentifiedEvent {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && 'id' in value && typeof value.id === 'string';
}

export function isStripeEvent(value: unknown): value is StripeEvent {
  return isIdentifiedEvent(value) && 'type' in value && typeof value.type === 'string';
}
