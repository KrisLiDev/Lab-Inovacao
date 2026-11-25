// ===== CONFIGURAÇÃO DO SITE =====

// Onde ficam os dados:
//  'local' -> sem servidor e sem banco (dados salvos no navegador). Funciona direto no GitHub Pages.
//  ''      -> usa o backend no mesmo servidor (pasta backend, npm start).
//  'https://seu-backend.exemplo.com' -> backend hospedado online (MySQL).
window.API_URL = 'local';

// Como é feito o segundo fator (MFA):
//  'email' -> código de 6 dígitos enviado ao e-mail cadastrado (precisa configurar o EmailJS abaixo).
//  'totp'  -> aplicativo autenticador (Google Authenticator etc.).
window.MFA_MODE = 'email';

// Envio de e-mail via EmailJS (https://www.emailjs.com). Preencha os 3 campos (passo a passo no README).
window.EMAILJS = {
  serviceId: '',   // ex.: 'service_ir114ym'
  templateId: '',  // ex.: 'template_83oc4nn'
  publicKey: ''    // ex.: 'raeqOvhYzRqTqC6rw'
};

// Perfis automáticos por e-mail (só no modo local). Quem se cadastrar com um destes e-mails
// recebe o perfil indicado. Coloque aqui o e-mail do professor e os da equipe. Exemplo:
//   'professor@exemplo.com': 'administrador',
//   'colega@exemplo.com': 'gestor'
window.PERFIS_POR_EMAIL = {
};

// Só para testes da equipe: se o envio de e-mail falhar, mostra o código na tela.
// Deixe false na versão que o professor vai usar.
window.DEMO_MFA = false;
