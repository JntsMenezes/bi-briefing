-- Keep-alive com gravação real no banco.
-- O ping antigo (só leitura via get_request_by_token) não impediu a pausa do
-- plano free em 19/10/2026. Agora o GitHub Action grava uma linha por dia.
--
-- Segurança (mesma linha do ADR 0001): anon não tem acesso à tabela;
-- só pode executar a função, que só mexe nesta tabela de uma linha.

create table if not exists public.keepalive (
  id         smallint primary key default 1 check (id = 1),
  pinged_at  timestamptz not null default now(),
  pings      bigint not null default 0
);

alter table public.keepalive enable row level security;
revoke all on public.keepalive from anon, authenticated;

create or replace function public.keepalive_ping()
returns timestamptz
language sql
security definer
set search_path = ''
as $$
  insert into public.keepalive as k (id, pinged_at, pings)
  values (1, now(), 1)
  on conflict (id) do update
    set pinged_at = now(), pings = k.pings + 1
  returning pinged_at;
$$;

revoke all on function public.keepalive_ping() from public;
grant execute on function public.keepalive_ping() to anon;
