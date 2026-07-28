begin;
select plan(18);

select has_table('public', 'agent_credentials', 'agent_credentials exists');
select has_table('public', 'contract_prices', 'contract_prices exists');
select has_table('public', 'agent_quotes', 'agent_quotes exists');
select has_table('public', 'agent_orders', 'agent_orders exists');
select has_table('public', 'agent_webhooks', 'agent_webhooks exists');
select has_table('private', 'agent_rate_limits', 'agent_rate_limits exists');
select has_table('private', 'agent_request_nonces', 'agent_request_nonces exists');
select has_table('private', 'agent_webhook_jobs', 'agent_webhook_jobs exists');

select has_function('public', 'issue_agent_credential', array['uuid', 'uuid']);
select has_function('public', 'consume_agent_rate_limit', array['text']);
select has_function('public', 'register_agent_nonce', array['text', 'text']);
select has_function(
  'public',
  'create_agent_order',
  array['uuid', 'uuid', 'uuid', 'jsonb', 'text', 'date']
);
select has_function('public', 'claim_agent_webhook_jobs', array['integer']);
select has_function('public', 'finish_agent_webhook_job', array['bigint', 'boolean', 'text']);

select is(
  (select relrowsecurity from pg_class where oid = 'public.agent_orders'::regclass),
  true,
  'agent_orders has RLS enabled'
);
select is(
  (select relrowsecurity from pg_class where oid = 'public.agent_credentials'::regclass),
  true,
  'agent_credentials has RLS enabled'
);
select is(
  has_function_privilege('anon', 'public.create_agent_order(uuid,uuid,uuid,jsonb,text,date)', 'EXECUTE'),
  false,
  'anon cannot execute atomic order creation'
);
select is(
  has_table_privilege('authenticated', 'public.agent_credentials', 'SELECT'),
  false,
  'authenticated clients cannot read HMAC verification keys'
);

select * from finish();
rollback;
