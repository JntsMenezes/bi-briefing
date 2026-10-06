-- Campos do briefing que o formulário já pedia mas nunca chegavam ao banco.
-- Todos texto livre: o formulário envia o rótulo escolhido (ex.: "Alta", "Até 2 semanas").

alter table requests
  add column if not exists area text,
  add column if not exists sponsor text,
  add column if not exists prioridade text,
  add column if not exists kpi_principal text,
  add column if not exists prazo text,
  add column if not exists dependencias text;

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
end;
$$;

grant execute on function answer_request_by_token(text, jsonb) to anon, authenticated;
