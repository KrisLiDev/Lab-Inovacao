# Smart Automation – Módulo de Autenticação, MFA e IAM

Projeto da disciplina **Laboratório de Inovação**. A Smart Automation é uma proposta de empresa de automação e
inteligência artificial para pequenos negócios locais (Brasília – DF). Este repositório contém o site do projeto
com um módulo de autenticação, múltiplo fator de autenticação (MFA) e gestão de identidade e acesso (IAM).

**Site online:** https://krislidev.github.io/Lab-Inovacao/

## Como testar (para o professor)
1. Abra o link do site. A primeira tela é sempre o login: o conteúdo só aparece após autenticar.
2. Clique em **Cadastro** e crie uma conta com um **e-mail real** (senha com no mínimo 8 caracteres).
3. Faça o **login** com e-mail e senha.
4. O sistema envia um **código de 6 dígitos para o e-mail cadastrado** (MFA). Verifique também a caixa de spam.
   O código vale 5 minutos, há 3 tentativas e é possível reenviar.
5. Digite o código para entrar. Em **Meu painel** aparecem seu nome, e-mail e perfil.
6. **Sair** encerra a sessão e volta ao login.

## Funcionalidades
- **Autenticação:** cadastro e login com senha protegida por hash (PBKDF2).
- **MFA:** segundo fator por código enviado ao e-mail (via EmailJS).
- **IAM / perfis de acesso:** `usuário` (padrão no cadastro), `gestor` e `administrador`.
  - Usuário: acessa as funcionalidades básicas.
  - Gestor: acessa também a área de gestão.
  - Administrador: acessa a área administrativa, altera o perfil dos usuários, reseta o MFA e exclui contas.
- Os perfis de gestor e administrador não podem ser escolhidos no cadastro: são definidos em `PERFIS_POR_EMAIL`
  (`config.js`) ou pelo administrador.

## Tecnologias
HTML, CSS e JavaScript (sem frameworks), Web Crypto API, EmailJS para envio dos códigos e GitHub Pages para hospedagem.
Existe também uma versão com backend (Node.js, Express e MySQL) na pasta `backend/`.

## Limitações conhecidas (versão acadêmica)
- Na versão publicada no GitHub Pages não há servidor: os cadastros ficam salvos **no navegador** de cada pessoa
  e a geração e a conferência do código MFA acontecem no próprio navegador. Isso atende ao propósito de demonstração,
  mas não é um nível de segurança de produção.
- A versão com backend (`backend/`) guarda usuários e sessões em MySQL. Nela o MFA é feito por **aplicativo
  autenticador** (TOTP), não por e-mail.
- O conteúdo do site é público no código-fonte da página; a tela de login controla o acesso à navegação e ao painel.

## Estrutura
- `index.html`, `style.css`, `script.js`, `config.js` – site (GitHub Pages)
- `backend/` – API, `schema.sql` e `.env.example` (opcional)

## Configuração do envio de e-mail (para a equipe)
1. Crie conta grátis em https://www.emailjs.com.
2. Email Services → Add New Service → Gmail → conecte uma conta → copie o **Service ID**.
3. Email Templates → Create New Template. Assunto: `Seu código de verificação - Smart Automation`.
   Conteúdo: `Olá, {{nome}}! Seu código de verificação é: {{codigo}}. Ele vale por 5 minutos.`
   Campo **To Email**: `{{to_email}}`. Salve e copie o **Template ID**.
4. Account → General → copie a **Public Key**.
5. Cole os 3 valores em `window.EMAILJS` no `config.js`.
6. Em `PERFIS_POR_EMAIL`, coloque o e-mail de quem deve entrar como `administrador` ou `gestor`.
7. Publique: Settings → Pages → Deploy from branch → `main` / root.

Plano gratuito do EmailJS: 200 e-mails por mês.

## Rodar a versão com backend (opcional)
1. Instale Node.js e MySQL e execute `backend/schema.sql` no MySQL Workbench.
2. Em `backend/`, copie `.env.example` para `.env` e preencha usuário e senha do MySQL.
3. Rode `npm install` e `npm start`.
4. Em `config.js`, use `window.API_URL = ''` (mesmo servidor) ou o endereço do backend hospedado.
   Em modo backend, use `window.MFA_MODE = 'totp'`.
5. Para uso online, hospede o `backend/` (Render, Railway etc.) e defina `ALLOWED_ORIGINS` com o endereço do GitHub Pages.

Contas de demonstração do backend (criadas automaticamente): `admin@smart.com` / `Admin@123` e
`gestor@smart.com` / `Gestor@123`. Troque as senhas ou use `SEED_DEMO=false`. Elas **não existem** na versão
do GitHub Pages (modo local).

## Equipe
Kristian Lima (Marketing e Parcerias), Letícia Santiago (Operações e Atendimento), Thauana Alves (Tecnologia e
Automação), Thayná Damasceno (Financeiro e Projetos) e Wesley Aragão (Suporte Técnico e Implantação).
