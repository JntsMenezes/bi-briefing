-- ============================================================
-- BI Briefing — schema inicial (Fase 1: uma organizacao so)
-- ============================================================

create extension if not exists pgcrypto;

-- ========== TABELAS ==========

create table organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  slug text not null unique,
  plan text not null default 'free' check (plan in ('free','pro')),
  stripe_customer_id text,
  created_at timestamptz not null default now()
);

create table profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text,
  avatar_url text,
  created_at timestamptz not null default now()
);

create table memberships (
  org_id uuid not null references organizations(id) on delete cascade,
  user_id uuid not null references profiles(id) on delete cascade,
  role text not null default 'member' check (role in ('owner','admin','member')),
  created_at timestamptz not null default now(),
  primary key (org_id, user_id)
);

create table workspaces (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  name text not null,
  slug text not null,
  color text default '#c2410c',
  created_by uuid references profiles(id),
  created_at timestamptz not null default now(),
  unique (org_id, slug)
);

create table workspace_members (
  workspace_id uuid not null references workspaces(id) on delete cascade,
  user_id uuid not null references profiles(id) on delete cascade,
  role text not null default 'member' check (role in ('admin','member')),
  primary key (workspace_id, user_id)
);

create table requests (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references workspaces(id) on delete cascade,
  org_id uuid not null references organizations(id) on delete cascade,
  created_by uuid references profiles(id),
  share_token text not null unique default encode(gen_random_bytes(16), 'hex'),
  status text not null default 'draft' check (status in ('draft','sent','answered','delivered','archived')),

  nome text, nome_dash text, audiencia text, freq text, stakeholders text,
  bi_existente text, story text, decisao text, ancora text, resolve_hoje text,
  referencia text, fonte text, excel_info text, metricas text, dimensoes text,
  visuals text, cor_hex text, paleta jsonb not null default '[]'::jsonb,
  modo_bi text, acesso text, urgencia text, nao_objetivos text, obs text,

  submitter_name text,
  readiness_score int not null default 0,
  effort_label text, usage_label text,
  readiness_svg text, wireframe_svg text,

  dashboard_url text,

  sent_at timestamptz, answered_at timestamptz, delivered_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table request_events (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null references requests(id) on delete cascade,
  type text not null check (type in ('sent','viewed','answered','delivered','commented')),
  actor_name text,
  meta jsonb,
  created_at timestamptz not null default now()
);

-- ========== INDICES ==========
create index on memberships (user_id);
create index on workspace_members (user_id);
create index on requests (workspace_id);
create index on requests (share_token);
create index on request_events (request_id);

-- ========== NOVO USUARIO -> cria profile automaticamente ==========
create or replace function handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  insert into profiles (id, full_name, avatar_url)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'name'),
    new.raw_user_meta_data->>'avatar_url'
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function handle_new_user();

-- ========== RLS ==========
alter table organizations enable row level security;
alter table profiles enable row level security;
alter table memberships enable row level security;
alter table workspaces enable row level security;
alter table workspace_members enable row level security;
alter table requests enable row level security;
alter table request_events enable row level security;

create policy "profiles: leitura para autenticados"
  on profiles for select to authenticated using (true);
create policy "profiles: cada um edita o proprio"
  on profiles for update to authenticated using (id = auth.uid());

create policy "organizations: membros leem sua org"
  on organizations for select to authenticated using (
    id in (select org_id from memberships where user_id = auth.uid())
  );

create policy "memberships: usuario le suas proprias"
  on memberships for select to authenticated using (user_id = auth.uid());

create policy "workspaces: membros da org leem"
  on workspaces for select to authenticated using (
    org_id in (select org_id from memberships where user_id = auth.uid())
  );
create policy "workspaces: membros da org criam"
  on workspaces for insert to authenticated with check (
    org_id in (select org_id from memberships where user_id = auth.uid())
  );

create policy "workspace_members: usuario le as suas"
  on workspace_members for select to authenticated using (user_id = auth.uid());
create policy "workspace_members: admin/owner da org gerencia"
  on workspace_members for all to authenticated using (
    workspace_id in (
      select w.id from workspaces w
      join memberships m on m.org_id = w.org_id
      where m.user_id = auth.uid() and m.role in ('owner','admin')
    )
  );

create policy "requests: membros do workspace leem"
  on requests for select to authenticated using (
    workspace_id in (select workspace_id from workspace_members where user_id = auth.uid())
  );
create policy "requests: membros do workspace criam"
  on requests for insert to authenticated with check (
    workspace_id in (select workspace_id from workspace_members where user_id = auth.uid())
    and created_by = auth.uid()
  );
create policy "requests: membros do workspace atualizam"
  on requests for update to authenticated using (
    workspace_id in (select workspace_id from workspace_members where user_id = auth.uid())
  );

create policy "request_events: membros do workspace leem"
  on request_events for select to authenticated using (
    request_id in (
      select r.id from requests r
      join workspace_members wm on wm.workspace_id = r.workspace_id
      where wm.user_id = auth.uid()
    )
  );

-- ========== ACESSO PUBLICO POR TOKEN (sem login) ==========
-- Em vez de abrir a tabela pra "anon", duas funcoes controlam exatamente
-- o que um visitante sem login pode ver/alterar: so o pedido cujo token
-- ele tem em maos, e so enquanto o status for 'sent'.

create or replace function get_request_by_token(p_token text)
returns setof requests
language sql
security definer set search_path = public
as $$
  select * from requests where share_token = p_token and status = 'sent';
$$;
grant execute on function get_request_by_token(text) to anon, authenticated;

create or replace function answer_request_by_token(p_token text, p_payload jsonb)
returns void
language plpgsql
security definer set search_path = public
as $$
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
end;
$$;
grant execute on function answer_request_by_token(text, jsonb) to anon, authenticated;
