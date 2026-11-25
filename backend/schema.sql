CREATE DATABASE IF NOT EXISTS smart_automation CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE smart_automation;

CREATE TABLE IF NOT EXISTS usuario (
  id_usuario INT NOT NULL AUTO_INCREMENT,
  nome VARCHAR(100) NOT NULL,
  email VARCHAR(120) NOT NULL,
  senha_hash VARCHAR(100) NOT NULL,
  perfil VARCHAR(15) NOT NULL DEFAULT 'usuario',
  mfa_secret VARCHAR(64) NULL,
  criado_em DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id_usuario),
  UNIQUE KEY uq_usuario_email (email),
  CHECK (perfil IN ('usuario','gestor','administrador'))
);

CREATE TABLE IF NOT EXISTS sessao (
  token_hash CHAR(64) NOT NULL,
  id_usuario INT NOT NULL,
  expira_em DATETIME NOT NULL,
  mfa_ok TINYINT(1) NOT NULL DEFAULT 0,
  mfa_temp VARCHAR(64) NULL,
  tentativas INT NOT NULL DEFAULT 0,
  PRIMARY KEY (token_hash),
  INDEX idx_sessao_expira (expira_em),
  FOREIGN KEY (id_usuario) REFERENCES usuario(id_usuario) ON DELETE CASCADE
);
