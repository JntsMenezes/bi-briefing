-- Endurecimento de segurança e integridade (revisão do database-reviewer, 2026-10-07).
-- Ajustado ao app: share_token continua editável (botão "Regenerar link"),
-- e a validação de URL casa com o front, que já prefixa https:// antes de salvar.
begin;

-- 0. Schema privado para funções auxiliares (fora da API REST) -----------------
create schema if not exists private;
revoke all on schema private from public, anon;
grant usage on schema private to authenticated;

create or replace function private.co_member_ids() returns setof uuid
language sql stable security definer set search_path = public, pg_temp as $$
  select m2.user_id from memberships m1
  join memberships m2 on m2.org_id = m1.org_id
  where m1.user_id = auth.uid();
$$;
revoke all on function private.co_member_ids() from public, anon;
grant execute on function private.co_member_ids() to authenticated;

-- 1. Permissões de tabela: anon não acessa tabela nenhuma (só as RPCs) ---------
revoke all on all tables in schema public from anon;
revoke truncate, references, trigger on all tables in schema public from authenticated;
revoke insert, update, delete on public.memberships, public.organizations, public.request_events from authenticated;
revoke insert, delete on public.profiles from authenticated;
alter default privileges in schema public revoke all on tables from anon;

-- 2. Funções públicas por token ------------------------------------------------
-- Link público não precisa (nem deve) ver ids internos nem o link de entrega.
create or replace function public.get_request_by_token(p_token text)
returns setof requests language sql stable security definer set search_path = public, pg_temp as $$
  select (jsonb_populate_record(null::public.requests,
            to_jsonb(r) - array['org_id','workspace_id','created_by','dashboard_url'])).*
  from public.requests r where r.share_token = p_token and r.status = 'sent';
$$;

-- Agora falha quando o token não existe ou já foi respondido (antes "dava certo" sem gravar nada).
create or replace function public.answer_request_by_token(p_token text, p_payload jsonb)
returns void language plpgsql security definer set search_path = public, pg_temp as $$
begin
  update requests set
    nome = p_payload->>'nome',
    nome_dash = p_payload->>'nome_dash',
    audiencia = p_payload->>'audiencia',
    freq = p_payload->>'freq',
    stakeholders = p_payload->>'stakeholders',
    bi_existente = p_payload->>'bi_existente',
    story = p_payload->>'story',
    decisao = p_payload->>'decisao',
    ancora = p_payload->>'ancora',
    resolve_hoje = p_payload->>'resolve_hoje',
    referencia = p_payload->>'referencia',
    fonte = p_payload->>'fonte',
    excel_info = p_payload->>'excel_info',
    metricas = p_payload->>'metricas',
    dimensoes = p_payload->>'dimensoes',
    visuals = p_payload->>'visuals',
    cor_hex = p_payload->>'cor_hex',
    paleta = coalesce(p_payload->'paleta', '[]'::jsonb),
    modo_bi = p_payload->>'modo_bi',
    acesso = p_payload->>'acesso',
    urgencia = p_payload->>'urgencia',
    nao_objetivos = p_payload->>'nao_objetivos',
    obs = p_payload->>'obs',
    area = p_payload->>'area',
    sponsor = p_payload->>'sponsor',
    prioridade = p_payload->>'prioridade',
    kpi_principal = p_payload->>'kpi_principal',
    prazo = p_payload->>'prazo',
    dependencias = p_payload->>'dependencias',
    submitter_name = p_payload->>'submitter_name',
    readiness_score = coalesce((p_payload->>'readiness_score')::int, 0),
    effort_label = p_payload->>'effort_label',
    usage_label = p_payload->>'usage_label',
    readiness_svg = p_payload->>'readiness_svg',
    wireframe_svg = p_payload->>'wireframe_svg',
    status = 'answered',
    answered_at = now(),
    updated_at = now()
  where share_token = p_token and status = 'sent';
  if not found then
    raise exception 'link inválido ou já respondido' using errcode = 'P0002';
  end if;
end;
$$;

alter function public.handle_new_user() set search_path = public, pg_temp;
revoke execute on function public.get_request_by_token(text), public.answer_request_by_token(text, jsonb) from public;
grant  execute on function public.get_request_by_token(text), public.answer_request_by_token(text, jsonb) to anon, authenticated;
-- Só roda como trigger do cadastro; não precisa ficar exposta em /rest/v1/rpc.
revoke execute on function public.handle_new_user() from public, anon, authenticated;

-- 3. Políticas RLS reescritas (WITH CHECK nos updates, auth.uid() em select) ----
do $$ declare p record; begin
  for p in select policyname, tablename from pg_policies where schemaname = 'public'
    and tablename in ('organizations','profiles','memberships','workspaces','workspace_members','requests','request_events')
  loop execute format('drop policy %I on public.%I', p.policyname, p.tablename); end loop;
end $$;

create policy "organizations: membros leem sua org" on organizations for select to authenticated
  using (id in (select org_id from memberships where user_id = (select auth.uid())));

create policy "profiles: proprio e colegas de org" on profiles for select to authenticated
  using (id = (select auth.uid()) or id in (select private.co_member_ids()));
create policy "profiles: cada um edita o proprio" on profiles for update to authenticated
  using (id = (select auth.uid())) with check (id = (select auth.uid()));

create policy "memberships: usuario le as suas" on memberships for select to authenticated
  using (user_id = (select auth.uid()));

create policy "workspaces: membros da org leem" on workspaces for select to authenticated
  using (org_id in (select org_id from memberships where user_id = (select auth.uid())));
create policy "workspaces: owner/admin criam" on workspaces for insert to authenticated
  with check (org_id in (select org_id from memberships
              where user_id = (select auth.uid()) and role in ('owner','admin')));

create policy "workspace_members: le as suas ou administra" on workspace_members for select to authenticated
  using (user_id = (select auth.uid()) or workspace_id in (
    select w.id from workspaces w join memberships m on m.org_id = w.org_id
    where m.user_id = (select auth.uid()) and m.role in ('owner','admin')));
create policy "workspace_members: admin insere" on workspace_members for insert to authenticated
  with check (workspace_id in (select w.id from workspaces w join memberships m on m.org_id = w.org_id
    where m.user_id = (select auth.uid()) and m.role in ('owner','admin')));
create policy "workspace_members: admin altera" on workspace_members for update to authenticated
  using (workspace_id in (select w.id from workspaces w join memberships m on m.org_id = w.org_id
    where m.user_id = (select auth.uid()) and m.role in ('owner','admin')))
  with check (workspace_id in (select w.id from workspaces w join memberships m on m.org_id = w.org_id
    where m.user_id = (select auth.uid()) and m.role in ('owner','admin')));
create policy "workspace_members: admin remove" on workspace_members for delete to authenticated
  using (workspace_id in (select w.id from workspaces w join memberships m on m.org_id = w.org_id
    where m.user_id = (select auth.uid()) and m.role in ('owner','admin')));

create policy "requests: membros do workspace leem" on requests for select to authenticated
  using (workspace_id in (select workspace_id from workspace_members where user_id = (select auth.uid())));
create policy "requests: membros do workspace criam" on requests for insert to authenticated
  with check (created_by = (select auth.uid()) and workspace_id in
    (select workspace_id from workspace_members where user_id = (select auth.uid())));
create policy "requests: membros do workspace atualizam" on requests for update to authenticated
  using (workspace_id in (select workspace_id from workspace_members where user_id = (select auth.uid())))
  with check (workspace_id in (select workspace_id from workspace_members where user_id = (select auth.uid())));
create policy "requests: membros excluem pedidos nao respondidos" on requests for delete to authenticated
  using (status in ('draft','sent') and workspace_id in
    (select workspace_id from workspace_members where user_id = (select auth.uid())));

create policy "request_events: membros do workspace leem" on request_events for select to authenticated
  using (request_id in (select r.id from requests r join workspace_members wm
    on wm.workspace_id = r.workspace_id where wm.user_id = (select auth.uid())));

-- 4. Guarda de requests: org_id vem do workspace, created_by fixo, updated_at,
--    transições de status válidas. share_token NÃO é travado (Regenerar link).
create or replace function private.requests_guard() returns trigger
language plpgsql security definer set search_path = public, pg_temp as $$
begin
  select org_id into new.org_id from workspaces where id = new.workspace_id;
  if new.org_id is null then raise exception 'workspace inválido'; end if;

  if tg_op = 'INSERT' then
    if new.status = 'sent' then new.sent_at := coalesce(new.sent_at, now()); end if;
    return new;
  end if;

  new.created_by := old.created_by;
  new.updated_at := now();
  if new.status is distinct from old.status then
    if (old.status, new.status) not in (
        ('draft','sent'), ('draft','archived'),
        ('sent','draft'), ('sent','answered'), ('sent','archived'),
        ('answered','sent'), ('answered','delivered'), ('answered','archived'),
        ('delivered','answered'), ('delivered','archived'),
        ('archived','draft'), ('archived','sent'), ('archived','answered'), ('archived','delivered'))
    then raise exception 'transição de status inválida: % -> %', old.status, new.status; end if;
    if new.status = 'delivered' and coalesce(new.dashboard_url, '') = '' then
      raise exception 'informe o link do dashboard para entregar'; end if;
    if new.status = 'sent'      then new.sent_at      := coalesce(new.sent_at, now()); end if;
    if new.status = 'answered'  then new.answered_at  := coalesce(new.answered_at, now()); end if;
    if new.status = 'delivered' then new.delivered_at := coalesce(new.delivered_at, now()); end if;
  end if;
  return new;
end $$;
drop trigger if exists requests_guard on requests;
create trigger requests_guard before insert or update on requests
  for each row execute function private.requests_guard();

-- 5. Linha do tempo: request_events passa a ser preenchida ----------------------
--    ('viewed' fica de fora: robôs e o keep-alive iriam poluir).
create or replace function private.requests_events() returns trigger
language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if new.status in ('sent','answered','delivered')
     and (tg_op = 'INSERT' or new.status is distinct from old.status) then
    insert into request_events (request_id, type, actor_name)
    values (new.id, new.status,
      case when new.status = 'answered' then new.submitter_name
           else (select full_name from profiles where id = auth.uid()) end);
  end if;
  return null;
end $$;
drop trigger if exists requests_events on requests;
create trigger requests_events after insert or update of status on requests
  for each row execute function private.requests_events();

-- 6. Sair da org remove acesso aos workspaces; só membro da org entra no workspace
create or replace function private.memberships_cleanup() returns trigger
language plpgsql security definer set search_path = public, pg_temp as $$
begin
  delete from workspace_members wm using workspaces w
   where w.id = wm.workspace_id and w.org_id = old.org_id and wm.user_id = old.user_id;
  return old;
end $$;
drop trigger if exists memberships_cleanup on memberships;
create trigger memberships_cleanup after delete on memberships
  for each row execute function private.memberships_cleanup();

create or replace function private.wsm_check() returns trigger
language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if not exists (select 1 from memberships m join workspaces w on w.org_id = m.org_id
                 where w.id = new.workspace_id and m.user_id = new.user_id)
  then raise exception 'usuário não é membro da organização deste workspace'; end if;
  return new;
end $$;
drop trigger if exists wsm_check on workspace_members;
create trigger wsm_check before insert or update on workspace_members
  for each row execute function private.wsm_check();

revoke all on function private.requests_guard(), private.requests_events(),
  private.memberships_cleanup(), private.wsm_check() from public, anon, authenticated;

-- 7. Limites de tamanho e formato (o link público grava direto nessas colunas) --
do $$ declare cols text; begin
  select string_agg(format('char_length(coalesce(%I, '''')) <= 20000', column_name), ' and ') into cols
  from information_schema.columns where table_schema = 'public' and table_name = 'requests'
   and data_type = 'text' and column_name not in ('share_token','status','readiness_svg','wireframe_svg','dashboard_url');
  alter table public.requests drop constraint if exists requests_text_len;
  execute format('alter table public.requests add constraint requests_text_len check (%s)', cols);
end $$;

alter table requests drop constraint if exists requests_misc_chk;
alter table requests add constraint requests_misc_chk check (
  readiness_score between 0 and 100
  and jsonb_typeof(paleta) = 'array' and octet_length(paleta::text) <= 2000
  and (cor_hex is null or cor_hex = '' or cor_hex ~ '^#[0-9a-fA-F]{3,8}$')
  and char_length(coalesce(dashboard_url, '')) <= 2000
  and (dashboard_url is null or dashboard_url = '' or dashboard_url ~* '^https?://')
);

-- Defesa extra; a proteção principal é o DOMPurify no front.
alter table requests drop constraint if exists requests_svg_chk;
alter table requests add constraint requests_svg_chk check (
  (readiness_svg is null or readiness_svg = '' or (char_length(readiness_svg) <= 200000
     and readiness_svg ~* '^\s*(<\?xml[^>]*>\s*)?<svg'
     and readiness_svg !~* '<\s*(script|foreignobject|iframe|object|embed)|[\s"''/]on[a-z]+\s*=|javascript:|href\s*=\s*["'']?\s*(data:|https?:|//)|<!entity'))
  and
  (wireframe_svg is null or wireframe_svg = '' or (char_length(wireframe_svg) <= 200000
     and wireframe_svg ~* '^\s*(<\?xml[^>]*>\s*)?<svg'
     and wireframe_svg !~* '<\s*(script|foreignobject|iframe|object|embed)|[\s"''/]on[a-z]+\s*=|javascript:|href\s*=\s*["'']?\s*(data:|https?:|//)|<!entity'))
);

-- 8. Apagar um usuário não trava mais por causa de created_by; índices ---------
alter table requests   drop constraint if exists requests_created_by_fkey;
alter table requests   add  constraint requests_created_by_fkey   foreign key (created_by) references profiles(id) on delete set null;
alter table workspaces drop constraint if exists workspaces_created_by_fkey;
alter table workspaces add  constraint workspaces_created_by_fkey foreign key (created_by) references profiles(id) on delete set null;

create index if not exists requests_created_by_idx   on requests(created_by);
create index if not exists requests_org_id_idx       on requests(org_id);
create index if not exists workspaces_created_by_idx on workspaces(created_by);
drop index if exists requests_share_token_idx;  -- duplicava o índice único requests_share_token_key

commit;
