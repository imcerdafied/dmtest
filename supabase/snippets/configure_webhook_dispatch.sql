-- Run once after deploying agent-webhook-dispatcher.
-- Replace both placeholders. The token must match AGENT_WEBHOOK_DISPATCH_TOKEN.
--
-- Vault keeps these values out of the cron command and normal table access.
select vault.create_secret(
  'https://PROJECT_REF.supabase.co/functions/v1/agent-webhook-dispatcher',
  'agent_webhook_dispatch_url'
);
select vault.create_secret(
  'REPLACE_WITH_A_RANDOM_32_BYTE_TOKEN',
  'agent_webhook_dispatch_token'
);

select cron.schedule(
  'agent-webhook-dispatcher',
  '10 seconds',
  $$
  select net.http_post(
    url := (
      select decrypted_secret
      from vault.decrypted_secrets
      where name = 'agent_webhook_dispatch_url'
    ),
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'Authorization', 'Bearer ' || (
        select decrypted_secret
        from vault.decrypted_secrets
        where name = 'agent_webhook_dispatch_token'
      )
    ),
    body := '{}'::jsonb,
    timeout_milliseconds := 10000
  );
  $$
);
