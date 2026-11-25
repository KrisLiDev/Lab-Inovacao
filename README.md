# Smart Automation – Autenticação, MFA e IAM

## Jeito mais simples (sem servidor e sem banco)
O `config.js` vem em modo `local` com MFA por e-mail:
1. Crie conta grátis em https://www.emailjs.com.
2. Email Services → Add New Service → Gmail → conecte uma conta (a da equipe) → copie o **Service ID**.
3. Email Templates → Create New Template. Assunto: `Seu código de verificação - Smart Automation`.
   Conteúdo: `Olá, {{nome}}! Seu código de verificação é: {{codigo}}. Ele vale por 5 minutos.`
   Campo **To Email**: `{{to_email}}`. Salve e copie o **Template ID**.
4. Account → General → copie a **Public Key**.
5. Cole os 3 valores em `window.EMAILJS` no `config.js`.
6. Em `PERFIS_POR_EMAIL`, coloque o e-mail do professor como `administrador` (ele verá todas as áreas).
7. Suba tudo na raiz do GitHub e ative o Pages (Settings → Pages → Deploy from branch → `main` / root).
8. TESTE com um e-mail seu: cadastro, login, chegada do código e verificação.
Plano grátis do EmailJS: 200 e-mails por mês.

## Estrutura
- `index.html`, `style.css`, `script.js`, `config.js` – site (pode ir para o GitHub Pages)
- `backend/` – API, `schema.sql` e `.env.example`

## Rodar no computador
1. Instale Node.js e MySQL.
2. No MySQL Workbench, execute `backend/schema.sql`.
3. Na pasta `backend`: copie `.env.example` para `.env` e preencha usuário/senha do MySQL.
4. No terminal, dentro de `backend`: `npm install` e depois `npm start`.
5. Abra http://localhost:3000

## Deixar online (para o professor acessar)
1. Hospede o `backend/` em um serviço Node (ex.: Render, Railway) com um MySQL (o colega pode criar). Configure as variáveis do `.env` no painel do serviço.
2. No `.env` do serviço, defina `ALLOWED_ORIGINS=https://SEU-USUARIO.github.io`.
3. No `config.js`, coloque `window.API_URL = 'https://endereco-do-seu-backend'` e envie ao GitHub.
4. No GitHub: Settings → Pages → Deploy from branch → `main` / root.

## Contas de demonstração
- admin@smart.com / Admin@123 (administrador)
- gestor@smart.com / Gestor@123 (gestor)
Troque as senhas antes de expor o sistema (ou use `SEED_DEMO=false`).

## Perfis
usuário (cadastro padrão), gestor e administrador. Só o administrador altera perfis, reseta MFA e exclui contas.
