# Link público acessa o banco só por funções, nunca pela tabela

O solicitante preenche o briefing sem login, então o link público precisa ler e gravar um pedido como usuário anônimo. Em vez de liberar a tabela `requests` para `anon` com políticas de RLS, o acesso passa só por duas funções `security definer` (`get_request_by_token` e `answer_request_by_token`), que recebem o token e tocam apenas aquele pedido. Assim um link nunca enxerga dados de outro pedido, workspace ou organização, mesmo se uma política da tabela for escrita errada no futuro.
