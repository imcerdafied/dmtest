begin;
select plan(18);

select has_table('public', 'agent_credentials');
select has_table('public', 'contract_prices');
select has_table('public', 'agent_quotes');
select has_table('public', 'agent_orders');
select has_table('public', 'agent_webhooks');
select has_table('private', 'agent_rate_limits');
select has_table('private', 'agent_request_nonces');
select has_table('private', 'agent_webhook_jobs');

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
