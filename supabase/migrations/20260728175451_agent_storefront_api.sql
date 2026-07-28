create extension if not exists pgcrypto with schema extensions;
create extension if not exists pg_net with schema extensions;
create extension if not exists pg_cron with schema pg_catalog;

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

create table if not exists public.products (
  sku text primary key,
  principal_id uuid not null,
  name text not null,
  description text,
  category text,
  unit_of_measure text not null default 'each',
  list_price numeric(12,4) not null check (list_price >= 0),
  images jsonb not null default '[]'::jsonb check (jsonb_typeof(images) = 'array'),
  attributes jsonb not null default '{}'::jsonb check (jsonb_typeof(attributes) = 'object'),
  search_document tsvector generated always as (
    to_tsvector('english', coalesce(name, '') || ' ' || coalesce(description, ''))
  ) stored,
  updated_at timestamptz not null default now()
);

-- Compatibility for the minimum pre-existing products table described in the
-- brief. Existing unscoped rows remain hidden until principal_id is backfilled.
alter table public.products add column if not exists principal_id uuid;
alter table public.products add column if not exists unit_of_measure text not null default 'each';
alter table public.products add column if not exists images jsonb not null default '[]'::jsonb;
alter table public.products add column if not exists attributes jsonb not null default '{}'::jsonb;
alter table public.products add column if not exists updated_at timestamptz not null default now();
alter table public.products add column if not exists search_document tsvector generated always as (
  to_tsvector('english', coalesce(name, '') || ' ' || coalesce(description, ''))
) stored;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conrelid = 'public.products'::regclass
      and conname = 'products_principal_required'
  ) then
    alter table public.products
      add constraint products_principal_required
      check (principal_id is not null) not valid;
  end if;
end;
$$;

create table if not exists public.warehouse_inventory (
  sku text not null references public.products(sku) on update cascade on delete restrict,
  warehouse_id text not null,
  qty_available integer not null default 0 check (qty_available >= 0),
  qty_reserved integer not null default 0 check (qty_reserved >= 0),
  updated_at timestamptz not null default now(),
  primary key (sku, warehouse_id)
);

create table if not exists public.agent_credentials (
  id uuid primary key default gen_random_uuid(),
  agent_id uuid not null references auth.users(id) on delete cascade,
  principal_id uuid not null,
  api_key_hash text not null unique check (length(api_key_hash) = 64),
  -- This is the HMAC verification key encoded as lowercase hex, not an
  -- irreversible password hash. It is service-role-only and never returned.
  hmac_secret_hex text not null check (
    length(hmac_secret_hex) = 64 and hmac_secret_hex ~ '^[0-9a-f]+$'
  ),
  active boolean not null default true,
  created_at timestamptz not null default now(),
  last_used_at timestamptz
);

-- Compatibility with the Identity Standards draft, which named an unusable
-- irreversible secret_hash column. Existing credentials must be reissued.
alter table public.agent_credentials add column if not exists hmac_secret_hex text;
do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conrelid = 'public.agent_credentials'::regclass
      and conname = 'agent_credentials_hmac_secret_format'
  ) then
    alter table public.agent_credentials
      add constraint agent_credentials_hmac_secret_format
      check (
        hmac_secret_hex is not null
        and length(hmac_secret_hex) = 64
        and hmac_secret_hex ~ '^[0-9a-f]+$'
      ) not valid;
  end if;
end;
$$;

create table if not exists public.contract_prices (
  id uuid primary key default gen_random_uuid(),
  principal_id uuid not null,
  sku text not null references public.products(sku) on update cascade on delete restrict,
  unit_price numeric(12,4) not null check (unit_price >= 0),
  effective_from date not null,
  effective_to date,
  created_at timestamptz not null default now(),
  check (effective_to is null or effective_to >= effective_from),
  unique (principal_id, sku, effective_from)
);

create table if not exists public.agent_quotes (
  id uuid primary key default gen_random_uuid(),
  agent_id uuid not null references auth.users(id) on delete restrict,
  principal_id uuid not null,
  items jsonb not null check (jsonb_typeof(items) = 'array'),
  total_price numeric(12,2) not null check (total_price >= 0),
  expires_at timestamptz not null default (now() + interval '15 minutes'),
  used boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists public.agent_orders (
  id uuid primary key default gen_random_uuid(),
  quote_id uuid not null unique references public.agent_quotes(id) on delete restrict,
  agent_id uuid not null references auth.users(id) on delete restrict,
  principal_id uuid not null,
  po_number text,
  shipping_address jsonb not null check (jsonb_typeof(shipping_address) = 'object'),
  requested_ship_date date,
  status text not null default 'confirmed' check (
    status in ('confirmed', 'processing', 'shipped', 'delivered', 'cancelled')
  ),
  items jsonb not null check (jsonb_typeof(items) = 'array'),
  total_price numeric(12,2) not null check (total_price >= 0),
  tracking_numbers text[] not null default '{}',
  shipped_at timestamptz,
  estimated_delivery_at timestamptz,
  estimated_ship_date date,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.agent_webhooks (
  id uuid primary key default gen_random_uuid(),
  agent_id uuid not null references auth.users(id) on delete cascade,
  principal_id uuid not null,
  url text not null check (url ~ '^https://'),
  events text[] not null,
  signing_secret_hex text not null check (
    length(signing_secret_hex) = 64 and signing_secret_hex ~ '^[0-9a-f]+$'
  ),
  active boolean not null default true,
  created_at timestamptz not null default now(),
  check (events <@ array[
    'order.status_changed', 'order.shipped', 'order.cancelled'
  ]::text[])
);

create table if not exists private.agent_rate_limits (
  api_key_hash text not null,
  window_start timestamptz not null,
  request_count integer not null default 0 check (request_count >= 0),
  primary key (api_key_hash, window_start)
);

create table if not exists private.agent_request_nonces (
  api_key_hash text not null,
  nonce text not null,
  created_at timestamptz not null default now(),
  primary key (api_key_hash, nonce)
);

create table if not exists private.agent_webhook_jobs (
  id bigint generated always as identity primary key,
  webhook_id uuid not null references public.agent_webhooks(id) on delete cascade,
  event_id uuid not null default gen_random_uuid(),
  event_type text not null,
  payload jsonb not null,
  status text not null default 'pending' check (
    status in ('pending', 'processing', 'delivered', 'dead')
  ),
  attempts integer not null default 0,
  available_at timestamptz not null default now(),
  locked_at timestamptz,
  delivered_at timestamptz,
  last_error text,
  created_at timestamptz not null default now()
);

create table if not exists private.agent_api_events (
  id bigint generated always as identity primary key,
  request_id uuid not null,
  event_name text not null,
  agent_id uuid,
  principal_id uuid,
  route text not null,
  method text not null,
  status_code integer not null,
  duration_ms integer not null,
  error_code text,
  properties jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

alter table public.products enable row level security;
alter table public.warehouse_inventory enable row level security;
alter table public.agent_credentials enable row level security;
alter table public.contract_prices enable row level security;
alter table public.agent_quotes enable row level security;
alter table public.agent_orders enable row level security;
alter table public.agent_webhooks enable row level security;
alter table private.agent_rate_limits enable row level security;
alter table private.agent_request_nonces enable row level security;
alter table private.agent_webhook_jobs enable row level security;
alter table private.agent_api_events enable row level security;

revoke all on table
  public.agent_credentials,
  public.contract_prices,
  public.agent_quotes,
  public.agent_orders,
  public.agent_webhooks
from anon, authenticated;
revoke all on all tables in schema private from public, anon, authenticated;
grant usage on schema public to service_role;
grant all on table
  public.products,
  public.warehouse_inventory,
  public.agent_credentials,
  public.contract_prices,
  public.agent_quotes,
  public.agent_orders,
  public.agent_webhooks
to service_role;
grant usage on schema private to service_role;
grant all on all tables in schema private to service_role;
grant usage, select on all sequences in schema private to service_role;

create index if not exists products_principal_category_sku_idx
  on public.products (principal_id, category, sku);
create index if not exists products_principal_updated_idx
  on public.products (principal_id, updated_at);
create index if not exists products_search_idx
  on public.products using gin (search_document);
create index if not exists inventory_sku_updated_idx
  on public.warehouse_inventory (sku, updated_at);
create index if not exists contract_prices_lookup_idx
  on public.contract_prices (principal_id, sku, effective_from desc, effective_to);
create index if not exists agent_quotes_owner_expiry_idx
  on public.agent_quotes (agent_id, expires_at);
create index if not exists agent_orders_owner_created_idx
  on public.agent_orders (agent_id, created_at desc);
create index if not exists agent_webhooks_owner_idx
  on public.agent_webhooks (agent_id, active);
create index if not exists webhook_jobs_claim_idx
  on private.agent_webhook_jobs (status, available_at, created_at);
create index if not exists agent_api_events_created_idx
  on private.agent_api_events (created_at desc, event_name);

create or replace function public.issue_agent_credential(
  p_agent_id uuid,
  p_principal_id uuid
)
returns table (
  credential_id uuid,
  api_key text,
  hmac_secret text
)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_api_key text := 'ag_' || encode(extensions.gen_random_bytes(24), 'hex');
  v_secret text := encode(extensions.gen_random_bytes(32), 'hex');
  v_id uuid;
begin
  if exists (
    select 1
    from information_schema.columns
    where table_schema = 'public'
      and table_name = 'agent_credentials'
      and column_name = 'secret_hash'
  ) then
    execute $sql$
      insert into public.agent_credentials(
        agent_id, principal_id, api_key_hash, secret_hash, hmac_secret_hex
      ) values ($1, $2, $3, $4, $5)
      returning id
    $sql$
    into v_id
    using
      p_agent_id,
      p_principal_id,
      encode(extensions.digest(v_api_key, 'sha256'), 'hex'),
      encode(extensions.digest(v_secret, 'sha256'), 'hex'),
      v_secret;
  else
    insert into public.agent_credentials(
      agent_id, principal_id, api_key_hash, hmac_secret_hex
    ) values (
      p_agent_id,
      p_principal_id,
      encode(extensions.digest(v_api_key, 'sha256'), 'hex'),
      v_secret
    )
    returning id into v_id;
  end if;

  return query select v_id, v_api_key, v_secret;
end;
$$;

create or replace function public.consume_agent_rate_limit(p_api_key_hash text)
returns table (allowed boolean, retry_after integer, request_count integer)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_window timestamptz := date_trunc('minute', clock_timestamp());
  v_count integer;
begin
  insert into private.agent_rate_limits(api_key_hash, window_start, request_count)
  values (p_api_key_hash, v_window, 1)
  on conflict (api_key_hash, window_start)
  do update set request_count = private.agent_rate_limits.request_count + 1
  returning private.agent_rate_limits.request_count into v_count;

  delete from private.agent_rate_limits
  where window_start < v_window - interval '2 minutes';

  return query select
    v_count <= 300,
    greatest(1, 60 - extract(second from clock_timestamp())::integer),
    v_count;
end;
$$;

create or replace function public.register_agent_nonce(
  p_api_key_hash text,
  p_nonce text
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  delete from private.agent_request_nonces
  where created_at < clock_timestamp() - interval '10 minutes';

  insert into private.agent_request_nonces(api_key_hash, nonce)
  values (p_api_key_hash, p_nonce)
  on conflict do nothing;

  return found;
end;
$$;

create or replace function public.create_agent_order(
  p_quote_id uuid,
  p_agent_id uuid,
  p_principal_id uuid,
  p_shipping_address jsonb,
  p_po_number text default null,
  p_requested_ship_date date default null
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_quote public.agent_quotes%rowtype;
  v_item jsonb;
  v_allocation jsonb;
  v_order public.agent_orders%rowtype;
  v_estimated_ship_date date;
begin
  if p_shipping_address is null
     or jsonb_typeof(p_shipping_address) <> 'object'
     or p_shipping_address = '{}'::jsonb then
    raise exception using errcode = '22023', message = 'invalid_shipping_address';
  end if;

  select * into v_quote
  from public.agent_quotes
  where id = p_quote_id
    and agent_id = p_agent_id
    and principal_id = p_principal_id
  for update;

  if not found then
    raise exception using errcode = 'P0002', message = 'quote_not_found';
  end if;
  if v_quote.used then
    raise exception using errcode = '23505', message = 'quote_already_used';
  end if;
  if v_quote.expires_at <= clock_timestamp() then
    raise exception using errcode = '22000', message = 'quote_expired';
  end if;

  for v_item in select value from jsonb_array_elements(v_quote.items)
  loop
    v_estimated_ship_date := greatest(
      coalesce(v_estimated_ship_date, current_date),
      coalesce((v_item->>'estimated_ship_date')::date, current_date)
    );

    for v_allocation in
      select value from jsonb_array_elements(v_item->'allocations')
    loop
      update public.warehouse_inventory
      set qty_available = qty_available - (v_allocation->>'qty')::integer,
          qty_reserved = qty_reserved + (v_allocation->>'qty')::integer,
          updated_at = clock_timestamp()
      where sku = v_item->>'sku'
        and warehouse_id = v_allocation->>'warehouse_id'
        and qty_available >= (v_allocation->>'qty')::integer;

      if not found then
        raise exception using
          errcode = 'P0001',
          message = 'insufficient_inventory:' || (v_item->>'sku');
      end if;
    end loop;
  end loop;

  insert into public.agent_orders(
    quote_id, agent_id, principal_id, po_number, shipping_address,
    requested_ship_date, items, total_price, estimated_ship_date
  ) values (
    v_quote.id, v_quote.agent_id, v_quote.principal_id, p_po_number,
    p_shipping_address, p_requested_ship_date, v_quote.items,
    v_quote.total_price, greatest(v_estimated_ship_date, p_requested_ship_date)
  )
  returning * into v_order;

  update public.agent_quotes set used = true where id = v_quote.id;

  return jsonb_build_object(
    'order_id', v_order.id,
    'status', v_order.status,
    'estimated_ship_date', v_order.estimated_ship_date
  );
end;
$$;

create or replace function public.claim_agent_webhook_jobs(p_limit integer default 25)
returns table (
  job_id bigint,
  event_id uuid,
  event_type text,
  payload jsonb,
  url text,
  signing_secret_hex text,
  attempts integer
)
language plpgsql
security definer
set search_path = ''
as $$
begin
  return query
  with claimed as (
    select j.id
    from private.agent_webhook_jobs j
    join public.agent_webhooks w on w.id = j.webhook_id and w.active
    where j.status in ('pending', 'processing')
      and j.available_at <= clock_timestamp()
      and (j.locked_at is null or j.locked_at < clock_timestamp() - interval '2 minutes')
    order by j.created_at
    for update skip locked
    limit least(greatest(p_limit, 1), 100)
  ),
  updated as (
    update private.agent_webhook_jobs j
    set status = 'processing',
        locked_at = clock_timestamp(),
        attempts = j.attempts + 1
    from claimed
    where j.id = claimed.id
    returning j.*
  )
  select
    u.id, u.event_id, u.event_type, u.payload, w.url,
    w.signing_secret_hex, u.attempts
  from updated u
  join public.agent_webhooks w on w.id = u.webhook_id
  where w.active;
end;
$$;

create or replace function public.finish_agent_webhook_job(
  p_job_id bigint,
  p_delivered boolean,
  p_error text default null
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  update private.agent_webhook_jobs
  set status = case
        when p_delivered then 'delivered'
        when attempts >= 8 then 'dead'
        else 'pending'
      end,
      delivered_at = case when p_delivered then clock_timestamp() else null end,
      available_at = case
        when p_delivered then available_at
        else clock_timestamp() + make_interval(secs => least(300, power(2, attempts)::integer))
      end,
      locked_at = null,
      last_error = left(p_error, 1000)
  where id = p_job_id;
end;
$$;

create or replace function public.record_agent_api_event(
  p_request_id uuid,
  p_event_name text,
  p_agent_id uuid,
  p_principal_id uuid,
  p_route text,
  p_method text,
  p_status_code integer,
  p_duration_ms integer,
  p_error_code text default null,
  p_properties jsonb default '{}'::jsonb
)
returns void
language sql
security definer
set search_path = ''
as $$
  insert into private.agent_api_events(
    request_id, event_name, agent_id, principal_id, route, method,
    status_code, duration_ms, error_code, properties
  ) values (
    p_request_id, p_event_name, p_agent_id, p_principal_id, p_route, p_method,
    p_status_code, p_duration_ms, p_error_code, coalesce(p_properties, '{}'::jsonb)
  );
$$;

create or replace function private.enqueue_agent_order_webhooks()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_event text;
begin
  if old.status = new.status then
    return new;
  end if;

  v_event := case new.status
    when 'shipped' then 'order.shipped'
    when 'cancelled' then 'order.cancelled'
    else 'order.status_changed'
  end;

  insert into private.agent_webhook_jobs(webhook_id, event_type, payload)
  select
    w.id,
    event_types.event_type,
    jsonb_build_object(
      'order_id', new.id,
      'status', new.status,
      'previous_status', old.status,
      'tracking_numbers', new.tracking_numbers,
      'shipped_at', new.shipped_at,
      'updated_at', new.updated_at
    )
  from public.agent_webhooks w
  cross join lateral (
    select distinct requested.event_type
    from (values ('order.status_changed'::text), (v_event)) requested(event_type)
  ) event_types
  where w.agent_id = new.agent_id
    and w.principal_id = new.principal_id
    and w.active
    and event_types.event_type = any(w.events)
    and (
      event_types.event_type = 'order.status_changed'
      or event_types.event_type = v_event
    );

  return new;
end;
$$;

create or replace function private.set_agent_order_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at = clock_timestamp();
  return new;
end;
$$;

drop trigger if exists set_agent_order_updated_at on public.agent_orders;
create trigger set_agent_order_updated_at
before update on public.agent_orders
for each row execute function private.set_agent_order_updated_at();

drop trigger if exists enqueue_agent_order_webhooks on public.agent_orders;
create trigger enqueue_agent_order_webhooks
after update of status on public.agent_orders
for each row execute function private.enqueue_agent_order_webhooks();

revoke execute on function public.consume_agent_rate_limit(text) from public, anon, authenticated;
revoke execute on function public.issue_agent_credential(uuid, uuid) from public, anon, authenticated;
revoke execute on function public.register_agent_nonce(text, text) from public, anon, authenticated;
revoke execute on function public.create_agent_order(uuid, uuid, uuid, jsonb, text, date) from public, anon, authenticated;
revoke execute on function public.claim_agent_webhook_jobs(integer) from public, anon, authenticated;
revoke execute on function public.finish_agent_webhook_job(bigint, boolean, text) from public, anon, authenticated;
revoke execute on function public.record_agent_api_event(uuid, text, uuid, uuid, text, text, integer, integer, text, jsonb) from public, anon, authenticated;
revoke execute on all functions in schema private from public, anon, authenticated;
grant execute on function public.consume_agent_rate_limit(text) to service_role;
grant execute on function public.issue_agent_credential(uuid, uuid) to service_role;
grant execute on function public.register_agent_nonce(text, text) to service_role;
grant execute on function public.create_agent_order(uuid, uuid, uuid, jsonb, text, date) to service_role;
grant execute on function public.claim_agent_webhook_jobs(integer) to service_role;
grant execute on function public.finish_agent_webhook_job(bigint, boolean, text) to service_role;
grant execute on function public.record_agent_api_event(uuid, text, uuid, uuid, text, text, integer, integer, text, jsonb) to service_role;

comment on table public.agent_credentials is
  'Service-role-only machine credentials. hmac_secret_hex must never be exposed through the Data API.';
comment on function public.create_agent_order(uuid, uuid, uuid, jsonb, text, date) is
  'Atomically validates/consumes a quote, reserves inventory, and creates one order.';
