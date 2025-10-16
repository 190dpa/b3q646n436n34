require('dotenv').config();
const sgMail = require('@sendgrid/mail');
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const http = require('http');
const crypto = require('crypto');
const { PrismaClient } = require('@prisma/client');
const { Server } = require("socket.io");

// --- Configuração do SendGrid ---
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// --- Configuração do Servidor Web ---
const app = express();
const prisma = new PrismaClient();

const server = http.createServer(app); // Criamos um servidor HTTP a partir do Express
const io = new Server(server); // Iniciamos o Socket.IO no mesmo servidor

app.use(bodyParser.json()); // Para entender requisições com corpo em JSON
app.use(bodyParser.urlencoded({ extended: true })); // Para entender formulários HTML
const port = process.env.PORT || 3000;

const PgStore = require('connect-pg-simple')(session);

// ⚙️ Confia no proxy HTTPS do Render (necessário para cookies funcionarem)
app.set('trust proxy', 1);

// --- Configuração da Sessão ---
// Criamos o middleware de sessão para poder compartilhá-lo com o Socket.IO
const sessionMiddleware = session({
    store: new PgStore({
        conString: `${process.env.DATABASE_URL}?sslmode=require`, // SSL para Render
        createTableIfMissing: true, // Cria a tabela de sessões automaticamente
    }),
    secret: process.env.SESSION_SECRET || 'um-segredo-muito-forte', // Crie uma SESSION_SECRET no seu .env
    resave: false,
    saveUninitialized: false,
    cookie: { 
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 dias
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production', // só exige HTTPS se em produção
  },
});

app.use(sessionMiddleware); // Usamos o middleware no Express
io.use((socket, next) => { // E também no Socket.IO
    sessionMiddleware(socket.request, {}, next);
});

// --- Rota de Cadastro (`/api/cadastrar`) ---
app.post('/api/cadastrar', async (req, res) => {
    const { username, email, password } = req.body;

    // Validação básica
    if (!username || !email || !password || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ message: 'Por favor, forneça um nome de usuário, e-mail válido e uma senha.' });
    }

    // Verifica se o usuário já existe (verificado ou pendente)
    const existingUser = await prisma.user.findUnique({ where: { email } });
    const pendingUser = await prisma.pendingUser.findUnique({ where: { email } });

    if (existingUser) {
        const message = existingUser.isBanned ? 'Esta conta foi banida.' : 'Este e-mail já está em uso por uma conta verificada.';
        return res.status(409).json({ message: message });
    }

    // Gera o código e hasheia a senha
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString(); // Gera um código de 6 dígitos
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    
    if (pendingUser) {
        // Se o usuário já está pendente, apenas atualiza o código e a senha
        await prisma.pendingUser.update({
            where: { email },
            data: { username, passwordHash, verificationCode }
        });
    } else {
        // Se não existe, cria um novo usuário pendente
        await prisma.pendingUser.create({ data: { email, username, passwordHash, verificationCode } });
    }

    // Configura o e-mail de verificação com o modelo bonito
    const bodyContent = `
        <p style="color: #b3b3b3; font-size: 16px; line-height: 24px; margin: 0 0 25px 0;">Olá, <strong>${username}</strong>!</p>
        <p style="color: #b3b3b3; font-size: 16px; line-height: 24px; margin: 0 0 35px 0;">Para completar seu cadastro no uberzer, por favor, use o código de 6 dígitos abaixo.</p>
        <style>
            @keyframes glow {
                0% { box-shadow: 0 0 4px #9b59b6; }
                50% { box-shadow: 0 0 16px #9b59b6, 0 0 24px #9b59b6; }
                100% { box-shadow: 0 0 4px #9b59b6; }
            }
            .code-box { animation: glow 2.5s infinite ease-in-out; }
        </style>
        <table border="0" cellpadding="0" cellspacing="0" width="100%">
            <tr>
                <td align="center" style="padding: 20px 0;">
                    <div class="code-box" style="background-color: #2a2a2a; border-radius: 8px; padding: 20px 30px; display: inline-block; border: 1px solid #444;">
                        <span style="color: #e0e0e0; font-size: 42px; letter-spacing: 15px; font-weight: 700; margin-left: 15px;">${verificationCode}</span>
                    </div>
                </td>
            </tr>
        </table>
        <p style="color: #b3b3b3; font-size: 16px; line-height: 24px; text-align: center; padding-top: 35px; margin: 0;">Volte para a página de verificação em nosso site e insira este código.</p>
    `;

    const emailHtml = createStyledEmail({
        title: 'Verifique sua Conta',
        bodyContent: bodyContent
    });

    const mailOptions = {
        from: { name: 'uberzer', email: process.env.EMAIL_USER },
        to: email,
        subject: 'Código de Verificação - uberzer',
        html: emailHtml
    };

    try {
        // Envia o e-mail em segundo plano, sem esperar pela resposta da SendGrid
        sgMail.send(mailOptions).catch(err => console.error("Erro ao enviar e-mail de verificação:", err));
        console.log(`E-mail de verificação enviado para ${email}`);
        res.status(200).json({ message: 'E-mail de verificação enviado! Por favor, verifique sua caixa de entrada.' });
    } catch (error) {
        // Este bloco catch agora é menos provável de ser atingido, mas é mantido por segurança.
        res.status(500).json({ message: 'Ocorreu um erro ao processar o cadastro.' });
    }
});

// --- Rota de Verificação (`/api/verificar`) ---
app.post('/api/verificar', async (req, res) => {
    const { email, verificationCode } = req.body;

    if (!email || !verificationCode) {
        return res.status(400).json({ message: 'E-mail e código de verificação são obrigatórios.' });
    }

    const pendingUser = await prisma.pendingUser.findFirst({
        where: { email, verificationCode },
    });

    // Verifica se existe um cadastro pendente e se o código está correto
    if (pendingUser) {
        // Verifica se um usuário com este e-mail já existe na tabela principal
        const existingUser = await prisma.user.findUnique({ where: { email } });

        if (!existingUser) {
            // Se o usuário não existe, cria um novo (o fluxo normal)
            await prisma.user.create({
                data: {
                    email: pendingUser.email,
                    username: pendingUser.username,
                    passwordHash: pendingUser.passwordHash,
                    coins: 1000, // Dá 1000 moedas iniciais
                    health: 100, // Vida inicial
                },
            });
        }

        // Remove o usuário da tabela de pendentes, pois a verificação foi bem-sucedida
        await prisma.pendingUser.delete({ where: { email } });

        console.log(`Usuário ${email} verificado com sucesso!`);
        res.status(200).json({ message: '✅ E-mail verificado com sucesso! Agora você pode fazer login.' });

        // Opcional: Enviar e-mail de boas-vindas/confirmação
        const welcomeEmailHtml = createStyledEmail({
            title: 'Bem-vindo ao uberzer!',
            bodyContent: `<p style="color: #b3b3b3; font-size: 16px; line-height: 24px;">Sua conta foi verificada com sucesso. Prepare-se para a aventura!</p>`
        });
        sgMail.send({
            to: email,
            from: { name: 'uberzer', email: process.env.EMAIL_USER },
            subject: 'Bem-vindo ao uberzer!',
            html: welcomeEmailHtml
        }).catch(err => console.error("Erro ao enviar e-mail de boas-vindas:", err)); // Envia em segundo plano

    } else {
        res.status(400).json({ message: 'Código de verificação inválido ou expirado.' });
    }
});

// --- Rota de Login (`/api/login`) ---
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'E-mail e senha são obrigatórios.' });
    }

    const user = await prisma.user.findUnique({ where: { email } });

    // 1. Verifica se o usuário existe
    if (!user) {
        return res.status(401).json({ message: 'Credenciais inválidas.' }); // 401 Unauthorized
    }

    // 2. Verifica se o usuário está banido (APÓS confirmar que ele existe)
    if (user.isBanned) {
        return res.status(403).json({ message: 'Esta conta foi banida.' }); // 403 Forbidden
    }

    // 2. Compara a senha enviada com o hash armazenado
    const isMatch = await bcrypt.compare(password, user.passwordHash);

    if (!isMatch) {
        return res.status(401).json({ message: 'Credenciais inválidas.' });
    }

    // 3. Se tudo estiver correto, cria a sessão
    req.session.user = {
        id: user.id,
        email: email,
        username: user.username,
        isAdmin: user.isAdmin
    };

    req.session.save((err) => {
        if (err) return res.status(500).json({ message: 'Não foi possível salvar a sessão.' });
        res.status(200).json({ message: 'Login bem-sucedido!', redirectTo: '/dashboard' });
    });
});

// --- Rota de Logout (`/api/logout`) ---
app.get('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ message: 'Não foi possível fazer logout.' });
        }
        res.redirect('/login');
    });
});

// --- Middleware para proteger rotas ---
async function isAuthenticated(req, res, next) {
    if (req.session.user) {
        try {
            const user = await prisma.user.findUnique({ where: { id: req.session.user.id } });
            if (user && !user.isBanned) {
                return next();
            } else {
                req.session.destroy(() => {
                    res.redirect('/login');
                });
            }
        } catch (error) {
            req.session.destroy(() => {
                res.redirect('/login');
            });
        }
    } else {
        res.redirect('/login');
    }
}

// --- Middleware para proteger rotas de Admin ---
function isAdmin(req, res, next) {
    if (req.session.user && req.session.user.isAdmin) {
        return next();
    }
    res.status(403).send('<h1>403 - Acesso Negado</h1>');
}

/**
 * Registra uma ação do administrador no banco de dados.
 * @param {string} adminUsername - O nome do admin que realizou a ação.
 * @param {string} action - O tipo da ação (ex: 'BAN_USER').
 * @param {string} details - Uma descrição detalhada da ação.
 */
async function logAdminAction(adminUsername, action, details) {
    try {
        await prisma.adminLog.create({
            data: { adminName: adminUsername, action, details },
        });
    } catch (error) {
        console.error("Falha ao registrar ação do admin:", error);
    }
}

// --- Módulo de Renderização de Páginas ---
// Centraliza todo o CSS e a estrutura HTML para um design coeso e fácil manutenção.

const mainStyleSheet = `
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap');
        :root {
            --bg-dark-primary: #121212; --bg-dark-secondary: #1e1e1e; --bg-dark-tertiary: #2a2a2a;
            --text-light-primary: #e0e0e0; --text-light-secondary: #b3b3b3;
            --accent-primary: #9b59b6; --accent-secondary: #8e44ad;
            --admin-accent: #f1c40f; --danger-accent: #e74c3c; --success-accent: #2ecc71; --info-accent: #3498db;
        }
        * { box-sizing: border-box; }
        body { font-family: 'Poppins', sans-serif; background-color: var(--bg-dark-primary); color: var(--text-light-primary); margin: 0; line-height: 1.6; }
        h1, h2 { color: var(--accent-primary); font-weight: 700; }
        a { color: var(--accent-primary); text-decoration: none; }
        a:hover { color: var(--accent-secondary); }
        
        /* --- Layout de Autenticação --- */
        .auth-layout { display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 20px; }
        .auth-container { background-color: var(--bg-dark-secondary); padding: 40px; border-radius: 12px; box-shadow: 0 10px 40px rgba(0,0,0,0.7); width: 100%; max-width: 420px; text-align: center; border-top: 4px solid var(--accent-primary); }
        .auth-container h1 { margin-top: 0; margin-bottom: 30px; }
        .form-group { margin-bottom: 20px; text-align: left; }
        .form-group label { display: block; margin-bottom: 8px; font-weight: 600; font-size: 0.9em; color: var(--text-light-secondary); }
        .form-group input { width: 100%; padding: 12px 15px; border-radius: 8px; border: 1px solid #444; background-color: var(--bg-dark-tertiary); color: var(--text-light-primary); font-size: 1em; }
        .btn { display: inline-block; width: 100%; padding: 12px; border: none; border-radius: 8px; background-color: var(--accent-primary); color: #fff; font-size: 1.1em; font-weight: 600; cursor: pointer; transition: all 0.2s; }
        .btn:hover { background-color: var(--accent-secondary); transform: translateY(-2px); }
        .auth-link { margin-top: 25px; font-size: 0.9em; }
        .error-message { color: var(--danger-accent); margin-top: 15px; display: none; font-weight: 600; }

        /* --- Layout do Dashboard --- */
        .dashboard-layout { display: flex; }
        #sidebar { width: 260px; background-color: var(--bg-dark-secondary); height: 100vh; padding: 20px 0; position: fixed; left: -260px; transition: left 0.3s ease; z-index: 1000; display: flex; flex-direction: column; }
        #sidebar.open { left: 0; }
        #sidebar .sidebar-header { padding: 0 20px 20px 20px; font-size: 1.5em; font-weight: 700; color: var(--accent-primary); border-bottom: 1px solid #333; }
        #sidebar nav { flex-grow: 1; }
        #sidebar a { padding: 15px 20px; text-decoration: none; font-size: 1.1em; color: var(--text-light-secondary); display: block; transition: background-color 0.2s; border-left: 4px solid transparent; }
        #sidebar a:hover { background-color: var(--bg-dark-tertiary); color: var(--text-light-primary); }
        #sidebar a.active { border-left-color: var(--accent-primary); color: var(--text-light-primary); font-weight: 600; }
        #sidebar .sidebar-footer { padding: 20px; border-top: 1px solid #333; }
        #main-content { flex-grow: 1; padding: 30px; margin-left: 0; transition: margin-left 0.3s ease; }
        #main-content.shifted { margin-left: 260px; }
        #menu-toggle { font-size: 24px; cursor: pointer; background: var(--bg-dark-tertiary); color: white; border: none; padding: 10px 15px; position: fixed; top: 15px; left: 15px; z-index: 1001; border-radius: 8px; }

        /* --- Componentes Gerais --- */
        .card { background: var(--bg-dark-secondary); padding: 20px; border-radius: 12px; margin-bottom: 20px; }
        .char-card { background: var(--bg-dark-secondary); padding: 15px; border-radius: 8px; border-left: 5px solid; transition: transform 0.2s; }
        .char-card:hover { transform: translateY(-5px); }
        .char-rarity { font-weight: bold; font-size: 0.9em; margin-bottom: 5px; }
        .char-name { font-size: 1.2em; font-weight: 600; }
        .char-ability { font-size: 0.9em; color: var(--text-light-secondary); margin-top: 10px; }
        .characters-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 20px; margin-top: 20px; }
        
        /* --- Painel de Admin --- */
        .admin-section { margin-bottom: 40px; }
        .admin-section h2 { border-bottom: 2px solid var(--admin-accent); padding-bottom: 10px; color: var(--admin-accent); }
        .user-list { list-style: none; padding: 0; }
        .user-list-item { background: var(--bg-dark-tertiary); padding: 15px; margin-bottom: 10px; border-radius: 8px; display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 15px; }
        .user-list-item a { color: var(--text-light-primary); text-decoration: none; display: block; width: 100%; }
        .user-list-item a:hover { background-color: rgba(255,255,255,0.05); }
        .ticket-link { color: var(--text-light-primary); text-decoration: none; }
        .ticket-link:hover { text-decoration: underline; }

        /* --- Chat do Ticket --- */
        .message-bubble { padding: 10px 15px; border-radius: 18px; margin-bottom: 10px; max-width: 70%; word-wrap: break-word; }
        .user-message { background-color: var(--accent-primary); color: white; margin-left: auto; border-bottom-right-radius: 4px; }
        .admin-message { background-color: var(--bg-dark-tertiary); color: var(--text-light-primary); margin-right: auto; border-bottom-left-radius: 4px; }
        .user-info { font-weight: 600; }
        .user-info span { font-weight: 400; color: var(--text-light-secondary); font-size: 0.9em; }
        .admin-form { display: flex; align-items: center; gap: 10px; }
        .admin-form input { padding: 8px; }
        .admin-form .btn-small { padding: 8px 12px; font-size: 0.9em; width: auto; }
        .btn-danger { background-color: var(--danger-accent); } .btn-danger:hover { background-color: #c0392b; }
        .btn-success { background-color: var(--success-accent); } .btn-success:hover { background-color: #27ae60; }
        .btn-info { background-color: var(--info-accent); } .btn-info:hover { background-color: #2980b9; }

        /* --- Animações --- */
        #fight-animation { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: #111; z-index: 2000; display: none; justify-content: center; align-items: center; overflow: hidden; }
        .side { position: absolute; width: 50%; height: 100%; background-size: cover; transition: transform 0.5s cubic-bezier(0.8, 0, 0.2, 1); }
        #left-side { left: 0; background-color: var(--accent-primary); transform: translateX(-100%); }
        #right-side { right: 0; background-color: var(--danger-accent); transform: translateX(100%); }
        #vs { position: absolute; font-size: 15vw; color: white; font-weight: bold; text-shadow: 0 0 20px black; transform: scale(3); opacity: 0; transition: all 0.3s ease-out 0.4s; }
        #fight-animation.active #left-side, #fight-animation.active #right-side { transform: translateX(0); }
        #fight-animation.active #vs { transform: scale(1); opacity: 1; }

        #roll-animation-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 2000; display: none; justify-content: center; align-items: center; backdrop-filter: blur(5px); }
        #roll-animation-overlay.active { display: flex; }
        #roll-card { transform: scale(0); transition: transform 0.5s cubic-bezier(0.34, 1.56, 0.64, 1); }
        #roll-animation-overlay.reveal #roll-card { transform: scale(1); }
        @keyframes chaty-glow { 0%, 100% { box-shadow: 0 0 20px 10px var(--admin-accent), 0 0 30px 15px #fff; } 50% { box-shadow: 0 0 40px 20px var(--admin-accent), 0 0 60px 30px #fff; } }
        #roll-animation-overlay.is-chatynirares { background: radial-gradient(circle, rgba(241,196,15,0.3) 0%, rgba(0,0,0,0.8) 70%); }
        #roll-animation-overlay.is-chatynirares #roll-card { animation: chaty-glow 2s infinite; }
    </style>
`;

const banHandlerScript = `
    <script>
        socket.on('banned', (data) => {
            const reason = data.reason || 'Nenhum motivo especificado.';
            const escapedReason = reason.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
            document.body.innerHTML = \`<div style="display: flex; flex-direction: column; justify-content: center; align-items: center; height: 100vh; background-color: #121212; color: #f0f0f0; text-align: center; padding: 20px;"><h1 style="color: #e53935; margin-bottom: 20px;">Você foi banido.</h1><p style="font-size: 1.2em;">Motivo: \${escapedReason}</p></div>\`;
        });
    </script>
`;

/**
 * Cria o HTML para um e-mail estilizado padrão.
 * @param {object} options
 * @param {string} options.title - O título principal no cabeçalho do e-mail.
 * @param {string} options.bodyContent - O conteúdo HTML principal do corpo do e-mail.
 * @param {object} [options.button] - Objeto opcional para um botão de ação.
 * @param {string} options.button.text - O texto do botão.
 * @param {string} options.button.link - O URL para onde o botão aponta.
 * @returns {string} O HTML completo do e-mail.
 */
function createStyledEmail({ title, bodyContent, button }) {
    const buttonHtml = button ? `
        <table border="0" cellpadding="0" cellspacing="0" width="100%">
            <tr>
                <td align="center" style="padding: 20px 0;">
                    <a href="${button.link}" target="_blank" style="background-color: #9b59b6; color: #ffffff; padding: 14px 28px; text-decoration: none; border-radius: 8px; font-weight: 600; display: inline-block;">${button.text}</a>
                </td>
            </tr>
        </table>
    ` : '';

    return `<!DOCTYPE html>
      <html lang="pt-BR">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${title}</title>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap');
            body { font-family: 'Poppins', sans-serif; }
        </style>
      </head>
      <body style="margin: 0; padding: 0; background-color: #121212; font-family: 'Poppins', sans-serif;">
          <table border="0" cellpadding="0" cellspacing="0" width="100%">
              <tr>
                  <td style="padding: 20px 0;">
                      <table align="center" border="0" cellpadding="0" cellspacing="0" width="600" style="border-collapse: collapse; background-color: #1e1e1e; border-radius: 12px; box-shadow: 0 10px 40px rgba(0,0,0,0.7); border-top: 4px solid #9b59b6;">
                          <!-- Header -->
                          <tr>
                              <td align="center" style="padding: 40px 0 30px 0;">
                                  <table border="0" cellpadding="0" cellspacing="0">
                                      <tr>
                                          <td align="center">
                                              <!-- Ícone SVG de escudo/verificação -->
                                              <svg width="60" height="60" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 2L3 5V11C3 16.55 6.84 21.74 12 23C17.16 21.74 21 16.55 21 11V5L12 2ZM10 17L6 13L7.41 11.59L10 14.17L16.59 7.58L18 9L10 17Z" fill="#9b59b6"/></svg>
                                          </td>
                                      </tr>
                                      <tr>
                                          <td align="center" style="padding-top: 15px; ">
                                              <h1 style="color: #e0e0e0; font-size: 28px; margin: 0; font-weight: 700;">${title}</h1>
                                          </td>
                                      </tr>
                                  </table>
                              </td>
                          </tr>
                          <tr><td style="padding: 30px 30px 40px 30px;">${bodyContent}${buttonHtml}</td></tr>
                          <!-- Footer -->
                          <tr>
                              <td align="center" style="padding: 20px; background-color: #121212; border-bottom-left-radius: 12px; border-bottom-right-radius: 12px;">
                                  <p style="color: #b3b3b3; font-size: 12px; margin: 0;">Se você não solicitou esta ação, pode ignorar este e-mail com segurança.</p>
                                  <p style="color: #9b59b6; font-size: 12px; margin: 10px 0 0 0;">© 2024 uberzer</p>
                              </td>
                          </tr>
                      </table>
                  </td>
              </tr>
          </table>
      </body>
      </html>`;
}

/**
 * Renderiza uma página de autenticação padrão.
 * @param {string} title - O título da página.
 * @param {string} content - O conteúdo HTML do corpo da página.
 * @returns {string} O HTML completo da página.
 */
function renderAuthPage(title, content) {
    return `<!DOCTYPE html>
    <html lang="pt-BR">
    <head><meta charset="UTF-8"><title>${title} - uberzer</title>${mainStyleSheet}</head>
    <body><div class="auth-layout">${content}</div></body>
    </html>`;
}

/**
 * Renderiza uma página do dashboard com a sidebar.
 * @param {object} session - A sessão do usuário.
 * @param {string} title - O título da página.
 * @param {string} content - O conteúdo HTML da área principal.
 * @returns {string} O HTML completo da página.
 */
function renderDashboardPage(session, title, content, pageScript = '') {
    const { username, isAdmin } = session.user;
    const sidebar = `
        <div id="sidebar">
            <div class="sidebar-header">uberzer</div>
            <nav>
                <a href="/dashboard">Dashboard</a>
                <a href="/chat">Chat Global</a>
                <a href="/tickets">Suporte</a>
                <a href="/fight">Lutar (+50 Moedas)</a>
                <a href="/characters">Meus Personagens</a>
                ${isAdmin ? '<a href="/admin" style="color: var(--admin-accent);">Admin Panel</a>' : ''}
            </nav>
            <div class="sidebar-footer">
                <a href="/api/logout">Sair</a>
            </div>
        </div>`;

    return `<!DOCTYPE html>
    <html lang="pt-BR">
    <head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>${title} - uberzer</title>${mainStyleSheet}</head>
    <body>
        <div class="dashboard-layout">
            ${sidebar}
            <main id="main-content">
                <button id="menu-toggle">&#9776;</button>
                ${content}
            </main>
        </div>
        <script src="/socket.io/socket.io.js"></script>
        <script>
            const menuToggle = document.getElementById('menu-toggle');
            const sidebar = document.getElementById('sidebar');
            const mainContent = document.getElementById('main-content');
            const socket = io();
            menuToggle.addEventListener('click', () => {
                sidebar.classList.toggle('open');
                mainContent.classList.toggle('shifted');
            });
            ${pageScript}
        </script>
        ${banHandlerScript}
    </body>
    </html>`;
}

// --- Página de Cadastro (Formulário) ---
app.get('/register', (req, res) => {
    if (req.session.user) {
        return res.redirect('/dashboard');
    }
    const content = `
        <div class="auth-container">
            <h1>Criar Conta</h1>
            <form id="register-form">
                <div class="form-group">
                    <label for="username">Nome de Usuário</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="email">Email</label>
                    <input type="email" id="email" name="email" required>
                </div>
                <div class="form-group">
                    <label for="password">Senha</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit" class="btn">Cadastrar</button>
                <p id="error-message" class="error-message"></p>
            </form>
            <div class="auth-link">Já tem uma conta? <a href="/login">Faça login</a></div>
        </div>
        <script>
            document.getElementById('register-form').addEventListener('submit', async (e) => {
                e.preventDefault();
                const username = e.target.username.value;
                const email = e.target.email.value;
                const password = e.target.password.value;
                const errorMessage = document.getElementById('error-message');

                const response = await fetch('/api/cadastrar', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, email, password })
                });

                const data = await response.json();
                if (!response.ok) {
                    errorMessage.textContent = data.message || 'Erro no servidor (' + response.status + '). Tente novamente.';
                    errorMessage.style.display = 'block';
                    return;
                }

                if (data.message.includes('enviado')) { // Sucesso
                    window.location.href = '/verify?email=' + encodeURIComponent(email);
                } else {
                    errorMessage.textContent = data.message;
                    errorMessage.style.display = 'block';
                }
            });
        </script>
    `;
    res.send(renderAuthPage('Cadastro', content));
});

// --- Página de Verificação (Formulário) ---
app.get('/verify', (req, res) => {
    const email = req.query.email;
    if (!email) {
        return res.redirect('/register');
    }
    const content = `
        <div class="auth-container">
            <h1>Verifique seu Email</h1>
            <p style="color: #aaa; margin-bottom: 20px;">Enviamos um código de 6 dígitos para <strong>${email}</strong>. Insira-o abaixo.</p>
            <form id="verify-form">
                <div class="form-group">
                    <label for="code">Código de Verificação</label>
                    <input type="text" id="code" name="code" required maxlength="6" pattern="[0-9]{6}" inputmode="numeric">
                </div>
                <button type="submit" class="btn">Verificar</button>
                <p id="error-message" class="error-message"></p>
            </form>
        </div>
        <script>
            document.getElementById('verify-form').addEventListener('submit', async (e) => {
                e.preventDefault();
                const code = e.target.code.value;
                const email = "${email}";
                const errorMessage = document.getElementById('error-message');

                const response = await fetch('/api/verificar', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, verificationCode: code })
                });

                const data = await response.json();
                if (!response.ok) {
                    errorMessage.textContent = data.message || 'Erro no servidor (' + response.status + '). Tente novamente.';
                    errorMessage.style.display = 'block';
                    return;
                }

                if (data.message.includes('sucesso')) {
                    alert('Conta verificada com sucesso! Você será redirecionado para o login.');
                    window.location.href = '/login';
                } else {
                    errorMessage.textContent = data.message;
                    errorMessage.style.display = 'block';
                }
            });
        </script>
    `;
    res.send(renderAuthPage('Verificação', content));
});

// --- Página de Login (Formulário) ---
app.get('/login', (req, res) => {
    // Se já estiver logado, redireciona para o dashboard
    if (req.session.user) {
        return res.redirect('/dashboard');
    }
    const content = `
        <div class="auth-container">
            <h1 style="color: var(--accent-primary); font-size: 2.5em; margin-bottom: 5px; letter-spacing: 2px;">uberzer</h1>
            <p style="color: #aaa; margin-top: 0; margin-bottom: 30px;">[o mundo rpg legal]</p>
            <h2 style="font-weight: 600; color: var(--text-light-secondary);">Login</h2>
            <form id="login-form">
                <div class="form-group">
                    <label for="email">Email</label>
                    <input type="email" id="email" name="email" required autocomplete="email">
                </div>
                <div class="form-group">
                    <label for="password">Senha</label>
                    <input type="password" id="password" name="password" required autocomplete="current-password">
                </div>
                <button type="submit" class="btn">Entrar</button>
                <p id="error-message" class="error-message"></p>
            </form>
            <div class="auth-link" style="display: flex; justify-content: space-between;">
                <a href="/forgot-password">Esqueceu a senha?</a>
                <span>Não tem uma conta? <a href="/register">Cadastre-se</a></span>
            </div>
        </div>
        <script>
            document.getElementById('login-form').addEventListener('submit', async (e) => {
                e.preventDefault();
                const email = e.target.email.value;
                const password = e.target.password.value;
                const errorMessage = document.getElementById('error-message');

                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });

                const data = await response.json().catch(() => null);

                if (!response.ok) {
                    errorMessage.textContent = data?.message || 'Erro no servidor (' + response.status + ').';
                    errorMessage.style.display = 'block';
                    return;
                }

                if (data && data.redirectTo) {
                    window.location.href = data.redirectTo;
                } else {
                    errorMessage.textContent = 'Ocorreu um erro inesperado.';
                    errorMessage.style.display = 'block';
                }
            });
        </script>
    `;
    res.send(renderAuthPage('Login', content));
});

// --- Página e API para Recuperação de Conta ---

// 1. Página para solicitar a recuperação
app.get('/forgot-password', (req, res) => {
    const content = `
        <div class="auth-container">
            <h1>Recuperar Conta</h1>
            <p style="color: #aaa; margin-bottom: 20px;">Insira seu e-mail e enviaremos um link para você redefinir sua senha.</p>
            <form id="forgot-form">
                <div class="form-group">
                    <label for="email">Email</label>
                    <input type="email" id="email" name="email" required>
                </div>
                <button type="submit" class="btn">Enviar Link de Recuperação</button>
                <p id="message" class="error-message" style="color: var(--success-accent);"></p>
            </form>
        </div>
        <script>
            document.getElementById('forgot-form').addEventListener('submit', async (e) => {
                e.preventDefault();
                const email = e.target.email.value;
                const messageEl = document.getElementById('message');
                
                const response = await fetch('/api/forgot-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email })
                });

                const data = await response.json();
                if (!response.ok) {
                    messageEl.textContent = data.message || 'Erro no servidor (' + response.status + ').';
                    return;
                }

                messageEl.textContent = data.message;
                messageEl.style.display = 'block';
            });
        </script>
    `;
    res.send(renderAuthPage('Recuperar Conta', content));
});

// 2. API para processar a solicitação e enviar o e-mail
app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!await prisma.user.findUnique({ where: { email } })) {
        // Responde com sucesso mesmo que o e-mail não exista para não revelar quais e-mails estão cadastrados
        return res.status(200).json({ message: 'Se um usuário com este e-mail existir, um link de recuperação foi enviado.' });
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expires = Date.now() + 3600000; // 1 hora de validade
    await prisma.passwordReset.create({ data: { email, token, expires: new Date(expires) } });

    const resetLink = `${process.env.BASE_URL || `http://localhost:${port}`}/reset-password?token=${token}`;

    const emailHtml = createStyledEmail({
        title: 'Redefinição de Senha',
        bodyContent: `<p style="color: #b3b3b3; font-size: 16px; line-height: 24px;">Você solicitou uma redefinição de senha. Clique no botão abaixo para criar uma nova senha. Se você não fez esta solicitação, pode ignorar este e-mail.</p>`,
        button: { text: 'Redefinir Senha', link: resetLink }
    });

    const mailOptions = {
        to: email,
        from: { name: 'Suporte uberzer', email: process.env.EMAIL_USER },
        subject: 'Redefinição de Senha - uberzer',
        html: emailHtml
    };

    try {
        await sgMail.send(mailOptions);
        res.status(200).json({ message: 'Se um usuário com este e-mail existir, um link de recuperação foi enviado.' });
    } catch (error) {
        console.error('Erro ao enviar e-mail de recuperação:', error);
        res.status(500).json({ message: 'Erro ao enviar e-mail.' });
    }
});

// 3. Página para redefinir a senha
app.get('/reset-password', async (req, res) => {
    const { token } = req.query;
    const resetData = await prisma.passwordReset.findUnique({ where: { token } });

    if (!resetData || resetData.expires < new Date()) {
        return res.status(400).send('<h1>Token inválido ou expirado.</h1><p>Por favor, solicite um novo link de recuperação.</p>');
    }

    const content = `
        <div class="auth-container">
            <h1>Crie uma Nova Senha</h1>
            <form action="/api/reset-password" method="POST">
                <input type="hidden" name="token" value="${token}">
                <div class="form-group">
                    <label for="password">Nova Senha</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit" class="btn">Salvar Nova Senha</button>
            </form>
        </div>
    `;
    res.send(renderAuthPage('Redefinir Senha', content));
});

// 4. API para salvar a nova senha
app.post('/api/reset-password', async (req, res) => {
    const { token, password } = req.body;
    const resetData = await prisma.passwordReset.findFirst({
        where: { token, expires: { gte: new Date() } }
    });

    if (!resetData) {
        return res.status(400).send('Token inválido ou expirado.');
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    await prisma.user.update({ where: { email: resetData.email }, data: { passwordHash } });

    await prisma.passwordReset.delete({ where: { token } }); // Invalida o token após o uso
    res.redirect('/login');
});

// --- Página do Dashboard (Protegida) ---
app.get('/dashboard', isAuthenticated, async (req, res) => {
  try {
    // Recarrega os dados do usuário para exibir informações atualizadas
    const user = await prisma.user.findUnique({
      where: { id: req.session.user.id },
      select: { username: true, coins: true, isAdmin: true }
    });

    if (!user) {
      req.session.destroy(() => res.redirect('/login'));
      return;
    }

    // Conteúdo do painel (pode editar à vontade)
    const content = `
      <div class="card">
        <h1>Bem-vindo, ${user.username}!</h1>
        <p>💰 Você tem <strong>${user.coins}</strong> moedas.</p>
      </div>
      <div class="card">
        <p>Use o menu à esquerda para navegar.</p>
      </div>
    `;

    // Renderiza com a sidebar e o layout bonito
    res.send(renderDashboardPage(req.session, 'Dashboard', content));

  } catch (err) {
    console.error('Erro ao renderizar dashboard:', err);
    res.status(500).send('<h1>Erro interno ao carregar o dashboard.</h1>');
  }
});

// --- Página do Chat Global (Protegida) ---
app.get('/chat', isAuthenticated, (req, res) => {
    const content = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Chat Global - uberzer</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body { margin: 0; padding-bottom: 3rem; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #1e1e1e; color: #f0f0f0; }
            #form { background: rgba(0, 0, 0, 0.15); padding: 0.25rem; position: fixed; bottom: 0; left: 0; right: 0; display: flex; height: 3rem; box-sizing: border-box; backdrop-filter: blur(10px); }
            #input { border: none; padding: 0 1rem; flex-grow: 1; border-radius: 2rem; margin: 0.25rem; background: #333; color: #fff; }
            #input:focus { outline: none; }
            #form > button { background: #bb86fc; border: none; padding: 0 1rem; margin: 0.25rem; border-radius: 3px; outline: none; color: #fff; cursor: pointer; }
            #messages { list-style-type: none; margin: 0; padding: 0; }
            #messages > li { padding: 0.5rem 1rem; }
            #messages > li:nth-child(odd) { background: #252526; }
            .system-message { color: #888; font-style: italic; }
            .username { font-weight: bold; color: #bb86fc; }
            #leave-chat {
                position: fixed;
                top: 10px;
                right: 10px;
                background: #e74c3c;
                color: white;
                padding: 8px 15px;
                border-radius: 5px;
                text-decoration: none;
                font-size: 0.9em;
                z-index: 10;
            }
        </style>
    </head>
    <body>
        <ul id="messages"></ul>
        <form id="form" action="">
            <input id="input" autocomplete="off" placeholder="Digite sua mensagem..." /><button>Enviar</button>
        </form>
        <a href="/dashboard" id="leave-chat">Sair do Chat</a>
        <script src="/socket.io/socket.io.js"></script>
        <script>
            const socket = io();
            const form = document.getElementById('form');
            const input = document.getElementById('input');
            const messages = document.getElementById('messages');
            const currentUser = "${req.session.user.username}";

            form.addEventListener('submit', function(e) {
                e.preventDefault();
                if (input.value) {
                    socket.emit('chat message', input.value);
                    input.value = '';
                }
            });

            socket.on('chat message', function(data) {
                const item = document.createElement('li');
                if (data.username === 'Sistema') {
                    item.classList.add('system-message');
                    item.textContent = data.msg;
                } else {
                    const userSpan = document.createElement('span');
                    userSpan.classList.add('username');
                    userSpan.textContent = data.username + ': ';
                    item.appendChild(userSpan);
                    item.appendChild(document.createTextNode(data.msg));
                }
                messages.appendChild(item);
                window.scrollTo(0, document.body.scrollHeight);
            });

        </script>
    </body></html>`;
    // Chat é uma página completa, então não usa o layout padrão do dashboard
    res.send(content.replace('</body>', `${banHandlerScript}</body>`));
});

// --- Página de Luta (Animação) ---
const opponents = [
    { name: 'Goblin Sorrateiro', power: 80, health: 60 },
    { name: 'Orc Brutamontes', power: 120, health: 150 },
    { name: 'Feiticeira do Pântano', power: 150, health: 90 },
    { name: 'Cavaleiro Caído', power: 200, health: 200 },
    { name: 'Lich Ancestral', power: 280, health: 180 },
    { name: 'Dragão Vermelho Jovem', power: 350, health: 400 },
];

app.get('/fight', isAuthenticated, async (req, res) => {
    const user = await prisma.user.findUnique({
        where: { id: req.session.user.id },
        select: { id: true, health: true, characters: true }
    });
    if (!user) return res.redirect('/login');
    
    const { buffs, totalPower, totalHealth } = calculatePlayerBuffs(user.characters);

    const content = `
        <div>
            <h1>Arena de Batalha</h1>
            <div class="card">
                <p>Seus personagens te concedem os seguintes bônus: <br><strong>${buffs.summary}</strong></p>
                <p>Seu Poder de Combate é: <strong>${totalPower}</strong> | Sua Vida Máxima é: <strong>${totalHealth}</strong></p>
            </div>
            <button id="find-fight-btn" class="btn">Procurar Luta</button>
        </div>

        <!-- Tela da Batalha (inicialmente oculta) -->
        <div id="battle-screen" style="display: none; margin-top: 20px;">
            <div style="display: flex; justify-content: space-around; text-align: center; margin-bottom: 20px;">
                <div>
                    <h2>Você</h2>
                    <div id="player-health" class="card" style="color: var(--success-accent); font-weight: bold;">HP: ${user.health}/${totalHealth}</div>
                </div>
                <div>
                    <h2 id="opponent-name">Oponente</h2>
                    <div id="opponent-health" class="card" style="color: var(--danger-accent); font-weight: bold;">HP: ???/???</div>
                </div>
            </div>
            <div id="battle-actions" class="card" style="text-align: center;">
                <h3>Seu Turno!</h3>
                <button class="btn" onclick="sendAction('fast_attack')">Ataque Rápido</button>
                <button class="btn" onclick="sendAction('strong_attack')">Ataque Forte</button>
                <button class="btn" onclick="sendAction('defend')">Defender</button>
            </div>
            <div id="battle-log" class="card" style="margin-top: 20px; max-height: 200px; overflow-y: auto;">
                <h4>Log de Combate</h4>
                <ul id="log-list" style="list-style: none; padding: 0; font-size: 0.9em;"></ul>
            </div>
        </div>
    `;
    const pageScript = `
            document.getElementById('find-fight-btn').addEventListener('click', async () => {
                document.getElementById('find-fight-btn').style.display = 'none';
                document.getElementById('battle-screen').style.display = 'block';
                socket.emit('start battle');
            });

            const logList = document.getElementById('log-list');
            const playerHealthEl = document.getElementById('player-health');
            const opponentHealthEl = document.getElementById('opponent-health');
            const opponentNameEl = document.getElementById('opponent-name');
            const battleActionsEl = document.getElementById('battle-actions');

            function addLog(message, color) {
                const li = document.createElement('li');
                li.textContent = message;
                if (color) li.style.color = color;
                logList.prepend(li);
            }

            function sendAction(action) {
                socket.emit('battle action', action);
                battleActionsEl.style.display = 'none'; // Desabilita ações até o próximo turno
            }

            socket.on('battle update', (data) => {
                addLog(data.log, data.logColor);
                
                // Atualiza a UI
                opponentNameEl.textContent = data.opponent.name;
                playerHealthEl.textContent = \`HP: \${data.player.health}/\${data.player.maxHealth}\`;
                opponentHealthEl.textContent = \`HP: \${data.opponent.health}/\${data.opponent.maxHealth}\`;

                if (data.isPlayerTurn) {
                    battleActionsEl.style.display = 'block';
                }
            });

            socket.on('battle end', (data) => {
                addLog(data.message, data.win ? 'var(--success-accent)' : 'var(--danger-accent)');
                battleActionsEl.style.display = 'none';
                setTimeout(() => {
                    alert(data.message);
                    window.location.reload();
                }, 1000);
            });
    `;
    res.send(renderDashboardPage(req.session, 'Lutar', content, pageScript));
});

// --- Página e API de Tickets de Suporte ---

app.get('/tickets', isAuthenticated, async (req, res) => {
    const userEmail = req.session.user.email;
    const userTickets = await prisma.ticket.findMany({
        where: { author: { email: userEmail } },
        orderBy: { createdAt: 'desc' }
    });

    const ticketsHtml = userTickets.map(ticket => `
        <a href="/ticket/${ticket.id}" class="ticket-link">
            <div class="card">
                <h3>${ticket.subject} <span style="font-size: 0.8em; color: ${ticket.status === 'open' ? 'var(--danger-accent)' : 'var(--success-accent)'};">(${ticket.status})</span></h3>
                <small style="color: var(--text-light-secondary);">${new Date(ticket.createdAt).toLocaleString('pt-BR')}</small>
            </div>
        </a>
    `).join('');

    const content = `
        <h1>Suporte</h1>
        <div class="card">
            <h2>Abrir Novo Ticket</h2>
            <form id="ticket-form">
                <div class="form-group">
                    <label for="subject">Assunto</label>
                    <input type="text" id="subject" name="subject" required>
                </div>
                <div class="form-group">
                    <label for="message">Mensagem</label>
                    <textarea id="message" name="message" rows="5" style="width: 100%; padding: 10px; border-radius: 8px; border: 1px solid #444; background-color: var(--bg-dark-tertiary); color: var(--text-light-primary); font-family: 'Poppins', sans-serif;"></textarea>
                </div>
                <button type="submit" class="btn">Enviar Ticket</button>
            </form>
        </div>
        <h2>Meus Tickets</h2>
        ${ticketsHtml || '<p>Você não abriu nenhum ticket ainda.</p>'}
        <script>
            document.getElementById('ticket-form').addEventListener('submit', async (e) => {
                e.preventDefault();
                const subject = e.target.subject.value;
                const message = e.target.message.value;
                const response = await fetch('/api/tickets/create', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ subject, message })
                });
                if (response.ok) {
                    alert('Ticket enviado com sucesso!');
                    window.location.reload();
                } else {
                    alert('Erro ao enviar ticket.');
                }
            });
        </script>
    `;
    res.send(renderDashboardPage(req.session, 'Suporte', content));
});

app.post('/api/tickets/create', isAuthenticated, async (req, res) => {
    const { subject, message } = req.body;
    const newTicket = await prisma.ticket.create({
        data: {
            subject,
            message,
            author: {
                connect: { id: req.session.user.id }
            },
            messages: {
                create: { content: message, authorName: req.session.user.username, isAdmin: req.session.user.isAdmin }
            }
        }
    });

    // Envia e-mail de confirmação para o usuário
    const emailHtml = createStyledEmail({
        title: 'Ticket de Suporte Recebido',
        bodyContent: `
            <p style="color: #b3b3b3; font-size: 16px; line-height: 24px;">Olá, ${req.session.user.username}.</p>
            <p style="color: #b3b3b3; font-size: 16px; line-height: 24px;">Recebemos seu ticket de suporte (ID: ${newTicket.id}) e nossa equipe irá analisá-lo em breve. Abaixo estão os detalhes:</p>
            <div style="background-color: #2a2a2a; padding: 15px; border-radius: 8px; margin: 20px 0; color: #e0e0e0;"><strong>Assunto:</strong> ${newTicket.subject}<br><strong>Mensagem:</strong> ${newTicket.message}</div>
        `
    });
    sgMail.send({
        to: req.session.user.email,
        from: { name: 'Suporte uberzer', email: process.env.EMAIL_USER },
        subject: `Confirmação do Ticket #${newTicket.id}: ${newTicket.subject}`,
        html: emailHtml
    }).catch(err => console.error("Erro ao enviar e-mail de confirmação de ticket:", err));

    // Notifica os admins em tempo real sobre o novo ticket
    io.to('admin-room').emit('new ticket', { ...newTicket, author: { username: req.session.user.username, email: req.session.user.email } });

    res.status(201).json({ message: 'Ticket criado com sucesso!', ticket: newTicket });
});

// --- Página de Visualização de um Ticket (Chat) ---
app.get('/ticket/:id', isAuthenticated, async (req, res) => {
    const ticketId = parseInt(req.params.id, 10);
    const userId = req.session.user.id;
    const isAdmin = req.session.user.isAdmin;

    const ticket = await prisma.ticket.findUnique({
        where: { id: ticketId },
        include: { 
            author: true,
            messages: {
                orderBy: { createdAt: 'asc' }
            }
        }
    });

    // Validação: o usuário deve ser o autor do ticket ou um admin
    if (!ticket || (!isAdmin && ticket.authorId !== userId)) {
        return res.status(403).send('Acesso negado.');
    } 

    const messagesHtml = ticket.messages.map(msg => `
        <div class="message-bubble ${msg.isAdmin ? 'admin-message' : 'user-message'}">
            <strong>${msg.authorName}:</strong><br>
            ${msg.content}
            <div style="font-size: 0.7em; text-align: right; opacity: 0.7;">${new Date(msg.createdAt).toLocaleTimeString('pt-BR')}</div>
        </div>
    `).join('');

    const pageContent = `
        <h1>Ticket #${ticket.id}: ${ticket.subject} (${ticket.status})</h1>
        <div class="card">
            <div id="message-container" style="display: flex; flex-direction: column; gap: 10px; margin-bottom: 20px; max-height: 50vh; overflow-y: auto; padding-right: 10px;">
                ${messagesHtml || '<p>Nenhuma mensagem ainda.</p>'}
            </div>
            <form id="reply-form">
                <div class="form-group">
                    <textarea id="reply-content" name="content" rows="3" required placeholder="Digite sua resposta..." style="width: 100%; padding: 10px; border-radius: 8px; border: 1px solid #444; background-color: var(--bg-dark-tertiary); color: var(--text-light-primary); font-family: 'Poppins', sans-serif;"></textarea>
                </div>
                <button type="submit" class="btn">Enviar Resposta</button>
            </form>
        </div>
    `;

    const pageScript = `
        const ticketId = ${ticket.id};
        const form = document.getElementById('reply-form');
        const contentInput = document.getElementById('reply-content');
        const messageContainer = document.getElementById('message-container');

        // Entra na sala do ticket ao carregar a página
        socket.emit('join ticket room', ticketId);

        form.addEventListener('submit', (e) => {
            e.preventDefault();
            const content = contentInput.value.trim();
            if (content) {
                socket.emit('ticket message', { ticketId, content });
                contentInput.value = '';
            }
        });

        socket.on('new ticket message', (msg) => {
            const messageEl = document.createElement('div');
            messageEl.classList.add('message-bubble', msg.isAdmin ? 'admin-message' : 'user-message');
            messageEl.innerHTML = \`<strong>\${msg.authorName}:</strong><br>\${msg.content}<div style="font-size: 0.7em; text-align: right; opacity: 0.7;">\${new Date(msg.createdAt).toLocaleTimeString('pt-BR')}</div>\`;
            messageContainer.appendChild(messageEl);
            messageContainer.scrollTop = messageContainer.scrollHeight; // Rola para a última mensagem
        });
    `;

    res.send(renderDashboardPage(req.session, `Ticket #${ticket.id}`, pageContent, pageScript));
});

// --- Lógica e Dados do Sistema de Sorteio de Personagens ---
const rarities = {
    COMUM: { name: 'Comum', color: '#9e9e9e', chance: 0.60 },
    RARO: { name: 'Raro', color: '#42a5f5', chance: 0.25 },
    LENDARIO: { name: 'Lendário', color: '#ab47bc', chance: 0.10 },
    MITICO: { name: 'Mítico', color: '#ff7043', chance: 0.045 },
    CHATYNIRARES: { name: 'Chatynirares', color: '#ffee58', chance: 0.005 }
};

const ROLL_COST = 150;

const charactersByRarity = {
    COMUM: [
        { name: 'Guerreiro de Taverna', ability: 'Golpe Básico', buff: { description: '+5 de Vida', type: 'health_flat', value: 5 } },
        { name: 'Mago Aprendiz', ability: 'Faísca Mágica', buff: { description: '+1% de Ataque', type: 'attack_percent', value: 0.01 } },
        { name: 'Ladino de Beco', ability: 'Ataque Furtivo Simples', buff: { description: '+1% de Defesa', type: 'defense_percent', value: 0.01 } }
    ],
    RARO: [
        { name: 'Cavaleiro de Aço', ability: 'Investida Poderosa', buff: { description: '+3% de Defesa', type: 'defense_percent', value: 0.03 } },
        { name: 'Feiticeiro Elemental', ability: 'Bola de Fogo', buff: { description: '+3% de Ataque', type: 'attack_percent', value: 0.03 } },
        { name: 'Arqueiro Élfico', ability: 'Flecha Precisa', buff: { description: '+20 de Vida', type: 'health_flat', value: 20 } }
    ],
    LENDARIO: [
        { name: 'Paladino da Luz Solar', ability: 'Cura Divina', buff: { description: '+10% de Defesa', type: 'defense_percent', value: 0.10 } },
        { name: 'Arquimago do Tempo', ability: 'Parar o Tempo (1s)', buff: { description: '+100 de Vida', type: 'health_flat', value: 100 } },
        { name: 'Mestre das Sombras', ability: 'Invisibilidade', buff: { description: '+8% de Ataque', type: 'attack_percent', value: 0.08 } }
    ],
    MITICO: [
        { name: 'Avatar do Dragão', ability: 'Sopro de Fogo em Cone', buff: { description: '+15% de Ataque', type: 'attack_percent', value: 0.15 } },
        { name: 'Portador da Lâmina Cósmica', ability: 'Golpe Meteoro', buff: { description: '+500 de Vida', type: 'health_flat', value: 500 } }
    ],
    CHATYNIRARES: [
        { name: 'Deus da Forja Estelar', ability: 'Criar Realidade', buff: { description: '+25% de Ataque e Defesa', type: 'all_percent', value: 0.25 } }
    ]
};

function rollCharacter() {
    const roll = Math.random();
    let cumulativeChance = 0;

    for (const rarityKey in rarities) {
        cumulativeChance += rarities[rarityKey].chance;
        if (roll < cumulativeChance) {
            const characterPool = charactersByRarity[rarityKey];
            const chosenCharacter = characterPool[Math.floor(Math.random() * characterPool.length)];
            return { ...chosenCharacter, rarity: rarities[rarityKey] };
        }
    }
}

/**
 * Calcula os buffs totais de uma lista de personagens.
 * @param {Array} characters - A lista de personagens do jogador.
 * @returns {{summary: string}} - Um objeto com a descrição resumida dos buffs.
 */
function calculatePlayerBuffs(characters = []) {
    const buffs = {
        attack_percent: 0,
        defense_percent: 0,
        health_flat: 0,
    };
    let basePower = 100; // Poder base de qualquer jogador
    let baseHealth = 100; // Vida base de qualquer jogador
    const allCharacterTemplates = Object.values(charactersByRarity).flat();

    for (const dbChar of characters) {
        const charTemplate = allCharacterTemplates.find(t => t.name === dbChar.name);
        if (charTemplate && charTemplate.buff) {
            const buff = charTemplate.buff;
            if (buff.type === 'all_percent') {
                buffs.attack_percent += buff.value;
                buffs.defense_percent += buff.value;
            } else if (buffs[buff.type] !== undefined) {
                buffs[buff.type] += buff.value;
            }
        }
    }
    const descriptions = [];
    if (buffs.attack_percent > 0) descriptions.push(`+${(buffs.attack_percent * 100).toFixed(0)}% de Ataque`);
    if (buffs.defense_percent > 0) descriptions.push(`+${(buffs.defense_percent * 100).toFixed(0)}% de Defesa`);
    if (buffs.health_flat > 0) descriptions.push(`+${buffs.health_flat} de Vida`);

    // Calcula o poder total
    const totalPower = Math.floor(basePower * (1 + buffs.attack_percent) * (1 + buffs.defense_percent) + buffs.health_flat);

    const totalHealth = baseHealth + buffs.health_flat;
    return { buffs: { summary: descriptions.join(', ') || 'Nenhum buff ativo' }, totalPower, totalHealth };
}

// --- Página de Personagens (Sorteio e Visualização) ---
app.get('/characters', isAuthenticated, async (req, res) => {
    const user = await prisma.user.findUnique({
        where: { id: req.session.user.id },
        include: { characters: true }
    });
    if (!user) return res.redirect('/login');

    const userCoins = user.coins || 0;
    const userCharacters = user.characters || [];
    
    let charactersHtml = userCharacters.map(char => `
        <div class="char-card" style="border-left-color: ${char.rarityColor};">
            <div class="char-rarity" style="color: ${char.rarityColor};">${char.rarityName}</div>
            <div class="char-name">${char.name}</div>
            <div class="char-ability">Buff: ${char.buffDescription}</div>
        </div>
    `).join('');


    const content = `
        <h1>Meus Personagens</h1>
        <div class="roll-section card">
            <p style="font-size: 1.2em; margin-bottom: 10px;">Seu Saldo: <span style="color: #ffee58;">${userCoins}</span> moedas</p>
            <button id="roll-btn" class="btn">Sortear Personagem (${ROLL_COST} moedas)</button>
        </div>
        <div class="characters-grid">${charactersHtml || '<p>Você ainda não tem personagens. Sorteie um!</p>'}</div>

        <!-- Overlay da Animação -->
        <div id="roll-animation-overlay">
            <div id="roll-card" class="char-card">
                <!-- Conteúdo será preenchido via JS -->
            </div>
        </div>

        <script>
            document.getElementById('roll-btn').addEventListener('click', async () => {
                const rollButton = document.getElementById('roll-btn');
                const overlay = document.getElementById('roll-animation-overlay');
                const rollCard = document.getElementById('roll-card');

                rollButton.disabled = true;
                rollButton.textContent = 'Sorteando...';
                overlay.classList.remove('is-chatynirares', 'reveal');
                overlay.classList.add('active');

                const response = await fetch('/api/character/roll', { method: 'POST' });
                
                if (response.ok) {
                    const result = await response.json();
                    // Preenche o card do resultado
                    rollCard.style.borderLeftColor = result.rarityColor;
                    rollCard.innerHTML = \`
                        <div class="char-rarity" style="color: \${result.rarityColor};">\${result.rarityName}</div>
                        <div class="char-name">\${result.name}</div>
                        <div class="char-ability">Buff: \${result.buffDescription}</div>\`;

                    // Se for Chatynirares, adiciona a classe especial
                    if (result.rarityName === 'Chatynirares') {
                        overlay.classList.add('is-chatynirares');
                    }

                    // Revela o card com animação
                    setTimeout(() => {
                        overlay.classList.add('reveal');
                    }, 500);

                    // Fecha a animação e recarrega a página
                    setTimeout(() => {
                        overlay.classList.remove('active', 'reveal', 'is-chatynirares');
                        window.location.reload();
                    }, 4000);

                } else {
                    const result = await response.json().catch(() => ({ message: 'Erro desconhecido no servidor.' }));
                    alert(result.message);
                    overlay.classList.remove('active'); // Fecha o overlay em caso de erro
                    rollButton.disabled = false;
                    rollButton.textContent = 'Sortear Personagem (' + ROLL_COST + ' moedas)';
                }
            });
        </script>
    `;
    res.send(renderDashboardPage(req.session, 'Meus Personagens', content));
});

// --- API para Sortear Personagem ---
app.post('/api/character/roll', isAuthenticated, async (req, res) => {
    const userId = req.session.user.id;
    const user = await prisma.user.findUnique({ where: { id: userId } });

    // Verifica se o usuário tem moedas suficientes
    if (!user || user.coins < ROLL_COST) {
        return res.status(402).json({ message: 'Moedas insuficientes! Você precisa de ' + ROLL_COST + ' moedas para sortear.' }); // 402 Payment Required
    }
    
    const newCharacter = rollCharacter();
    
    // Atualiza o saldo e adiciona o novo personagem em uma transação
    const [, createdCharacter] = await prisma.$transaction([
        prisma.user.update({
            where: { id: userId },
            data: { coins: { decrement: ROLL_COST } },
        }),
        prisma.character.create({
            data: {
                name: newCharacter.name,
                ability: newCharacter.ability,
                rarityName: newCharacter.rarity.name,
                rarityColor: newCharacter.rarity.color,
                buffDescription: newCharacter.buff.description,
                ownerId: userId,
            }
        })
    ]);
    
    res.status(200).json(createdCharacter);
});

// --- Página do Painel de Admin (Protegida) ---
app.get('/admin', isAuthenticated, isAdmin, async (req, res) => {
    const adminData = await prisma.user.findUnique({ where: { id: req.session.user.id } });
    const allUsers = await prisma.user.findMany({ where: { isBanned: false } });
    const allBannedUsers = await prisma.user.findMany({ where: { isBanned: true } });
    const openTickets = await prisma.ticket.findMany({ where: { status: 'open' }, include: { author: true } });
    const pendingAppeals = await prisma.banAppeal.findMany({ where: { status: 'pending' }, include: { user: true } });
    const activeGiftLinks = await prisma.giftLink.findMany({ where: { claimed: false, expiresAt: { gte: new Date() } }, orderBy: { createdAt: 'desc' } });
    const adminLogs = await prisma.adminLog.findMany({ orderBy: { createdAt: 'desc' }, take: 20 }); // Pega os últimos 20 logs

    let userListHtml = '';
    for (const userData of allUsers) {
        // Não mostra o próprio admin na lista de banimento
        if (userData.username !== process.env.ADMIN_USERNAME) {
            userListHtml += `
                <li class="user-list-item">
                    <div class="user-info">${userData.username} <span>(${userData.email})</span></div>
                    <form action="/api/admin/ban" method="POST" class="admin-form">
                        <input type="hidden" name="email" value="${userData.email}">
                        <input type="text" name="reason" placeholder="Motivo do banimento" required>
                        <button type="submit" class="btn-small btn-danger">Banir</button>
                    </form>
                    <form action="/api/admin/give-coins" method="POST" class="admin-form">
                        <input type="hidden" name="email" value="${userData.email}">
                        <input type="number" name="amount" placeholder="Doar Moedas" required min="1">
                        <button type="submit" class="btn-small btn-info">Doar</button>
                    </form>
                </li>
            `;
        }
    }

    let bannedUserListHtml = '';
    for (const userData of allBannedUsers) {
        bannedUserListHtml += `
            <li class="user-list-item">
                <div class="user-info">${userData.username} <span>(${userData.email})</span></div>
                <form action="/api/admin/unban" method="POST" class="admin-form">
                    <input type="hidden" name="email" value="${userData.email}">
                    <button type="submit" class="btn-small btn-success">Desbanir</button>
                </form>
            </li>
        `;
    }

    let openTicketsHtml = '';
    for (const ticket of openTickets) {
        openTicketsHtml += `
            <li class="user-list-item" style="flex-direction: column; align-items: flex-start;">
                <a href="/ticket/${ticket.id}" class="ticket-link" style="width: 100%;">
                    <div style="width: 100%; display: flex; justify-content: space-between; align-items: center;">
                        <strong>${ticket.subject}</strong>
                        <form action="/api/admin/tickets/close" method="POST" class="admin-form" onclick="event.stopPropagation()">
                            <input type="hidden" name="ticketId" value="${ticket.id}">
                            <button type="submit" class="btn-small btn-success">Fechar</button>
                        </form>
                    </div>
                </a>
                <small>De: ${ticket.author.username} (${ticket.author.email})</small>
            </li>
        `;
    }

    let adminLogsHtml = '';
    for (const log of adminLogs) {
        adminLogsHtml += `
            <li class="user-list-item" style="justify-content: flex-start; gap: 20px;">
                <span style="color: var(--admin-accent); font-weight: 600;">[${log.action}]</span>
                <span>${log.details}</span>
                <small style="margin-left: auto; color: var(--text-light-secondary);">
                    ${new Date(log.createdAt).toLocaleString('pt-BR')} por ${log.adminName}
                </small>
            </li>
        `;
    }

    let appealsHtml = '';
    for (const appeal of pendingAppeals) {
        appealsHtml += `
            <li class="user-list-item" style="flex-direction: column; align-items: flex-start;">
                <div class="user-info">${appeal.user.username} <span>(${appeal.user.email})</span></div>
                <p style="margin: 10px 0; color: var(--text-light-secondary); border-left: 2px solid var(--info-accent); padding-left: 10px;"><em>"${appeal.content}"</em></p>
                <div style="display: flex; gap: 10px; margin-top: 10px;">
                    <form action="/api/admin/appeals/approve" method="POST" class="admin-form">
                        <input type="hidden" name="appealId" value="${appeal.id}">
                        <button type="submit" class="btn-small btn-success">Aprovar (Desbanir)</button>
                    </form>
                    <form action="/api/admin/appeals/reject" method="POST" class="admin-form">
                        <input type="hidden" name="appealId" value="${appeal.id}">
                        <button type="submit" class="btn-small btn-danger">Rejeitar</button>
                    </form>
                </div>
            </li>
        `;
    }

    // Constrói a lista de personagens com a raridade incluída
    const allCharactersList = [];
    for (const rarityKey in charactersByRarity) {
        charactersByRarity[rarityKey].forEach(char => {
            allCharactersList.push({ ...char, rarity: rarities[rarityKey] });
        });
    }
    const characterOptionsHtml = allCharactersList.map(char => `<option value="${char.name}">${char.name} (${char.rarity.name})</option>`).join('');

    let giftLinksHtml = '';
    for (const link of activeGiftLinks) {
        const fullLink = `${process.env.BASE_URL || `http://localhost:${port}`}/claim-gift?token=${link.token}`;
        let giftDescription = '';
        if (link.giftType === 'COINS') {
            giftDescription = `${link.giftValue} Moedas`;
        } else if (link.giftType === 'CHARACTER') {
            giftDescription = `Personagem: ${link.giftValue}`;
        }
        giftLinksHtml += `
            <li class="user-list-item">
                <span>Presente: <strong>${giftDescription}</strong></span>
                <input type="text" value="${fullLink}" readonly onclick="this.select()" style="flex-grow: 1; background: #1e1e1e; border: 1px solid #444; color: var(--text-light-primary); padding: 5px;">
            </li>
        `;
    }

    const content = `
        <h1 style="color: var(--admin-accent);">Painel do Administrador</h1>

        <div class="admin-section">
            <h2>Gerenciar Moedas (Admin)</h2>
            <div class="card">
                <p>Seu saldo atual: <span style="color: #ffee58;">${adminData.coins}</span> moedas</p>
                <form action="/api/admin/give-coins" method="POST" class="admin-form">
                    <input type="hidden" name="email" value="${adminData.email}">
                    <input type="number" name="amount" placeholder="Quantidade para adicionar" required min="1">
                    <button type="submit" class="btn-small btn-info">Adicionar para mim</button>
                </form>
            </div>
        </div>

        <div class="admin-section">
            <h2>Gerar Links de Presente (Válido por 5 min)</h2>
            <div class="card">
                <form action="/api/admin/generate-gift-link" method="POST" class="admin-form" style="flex-direction: column; align-items: stretch;">
                    <div class="form-group">
                        <label for="giftType">Tipo de Presente</label>
                        <select name="giftType" id="giftType" onchange="toggleGiftValue()" style="width: 100%; padding: 10px;">
                            <option value="COINS">Moedas</option>
                            <option value="CHARACTER">Personagem</option>
                        </select>
                    </div>
                    <div id="coins-input" class="form-group">
                        <label for="coinsValue">Quantidade de Moedas</label>
                        <input type="number" name="coinsValue" placeholder="Ex: 500" min="1">
                    </div>
                    <div id="character-input" class="form-group" style="display: none;">
                        <label for="characterValue">Personagem</label>
                        <select name="characterValue" style="width: 100%; padding: 10px;">${characterOptionsHtml}</select>
                    </div>
                    <button type="submit" class="btn-small btn-info" style="width: 100%;">Gerar Link</button>
                </form>
            </div>
            <h3>Links Ativos</h3>
            <ul class="user-list">${giftLinksHtml || '<li class="user-list-item">Nenhum link de presente ativo.</li>'}</ul>
        </div>

        <div class="admin-section">
            <h2>Usuários Ativos</h2>
            <ul class="user-list" id="active-users-list">${userListHtml || '<li class="user-list-item">Nenhum usuário para gerenciar.</li>'}</ul>
            <template id="user-item-template">
                <li class="user-list-item">
                    <div class="user-info"></div>
                    <!-- Forms serão adicionados dinamicamente -->
                </li>
            </template>
        </div>
        <div class="admin-section">
            <h2>Usuários Banidos</h2>
            <ul class="user-list" id="banned-users-list">${bannedUserListHtml || '<li class="user-list-item">Nenhum usuário banido.</li>'}</ul>
        </div>

        <div class="admin-section">
            <h2 style="color: var(--info-accent);">Tickets Abertos</h2>
            <ul class="user-list" id="open-tickets-list">${openTicketsHtml || '<li class="user-list-item">Nenhum ticket aberto.</li>'}</ul>
        </div>

        <div class="admin-section">
            <h2 style="color: var(--info-accent);">Apelos de Banimento</h2>
            <ul class="user-list" id="ban-appeals-list">${appealsHtml || '<li class="user-list-item">Nenhum apelo pendente.</li>'}</ul>
        </div>

        <div class="admin-section">
            <h2 style="color: #bdc3c7;">Log de Ações Recentes</h2>
            <ul class="user-list">${adminLogsHtml || '<li class="user-list-item">Nenhuma ação registrada.</li>'}</ul>
        </div>
    `;

    const adminScript = `
        function toggleGiftValue() {
            const giftType = document.getElementById('giftType').value;
            if (giftType === 'COINS') {
                document.getElementById('coins-input').style.display = 'block';
                document.getElementById('character-input').style.display = 'none';
            } else {
                document.getElementById('coins-input').style.display = 'none';
                document.getElementById('character-input').style.display = 'block';
            }
        }
        toggleGiftValue(); // Run on page load

        socket.emit('join admin room'); // Admin entra na sala de notificações

        // --- Real-time para Tickets ---
        socket.on('new ticket', (ticket) => {
            const list = document.getElementById('open-tickets-list');
            const newItem = document.createElement('li');
            newItem.className = 'user-list-item';
            newItem.style.flexDirection = 'column';
            newItem.style.alignItems = 'flex-start';
            newItem.innerHTML = \`
                <a href="/ticket/\${ticket.id}" class="ticket-link" style="width: 100%;">
                    <div style="width: 100%; display: flex; justify-content: space-between; align-items: center;">
                        <strong>\${ticket.subject}</strong>
                        <form action="/api/admin/tickets/close" method="POST" class="admin-form" onclick="event.stopPropagation()">
                            <input type="hidden" name="ticketId" value="\${ticket.id}">
                            <button type="submit" class="btn-small btn-success">Fechar</button>
                        </form>
                    </div>
                </a>
                <small>De: \${ticket.author.username} (\${ticket.author.email})</small>
            \`;
            if (list.querySelector('.user-list-item').textContent.includes('Nenhum ticket')) {
                list.innerHTML = ''; // Limpa a mensagem "Nenhum ticket"
            }
            list.prepend(newItem);
        });

        // --- Real-time para Apelos ---
        socket.on('new appeal', (appeal) => {
            const list = document.getElementById('ban-appeals-list');
            const newItem = document.createElement('li');
            newItem.className = 'user-list-item';
            newItem.style.flexDirection = 'column';
            newItem.style.alignItems = 'flex-start';
            newItem.id = 'appeal-' + appeal.id;
            newItem.innerHTML = \`
                <div class="user-info">\${appeal.user.username} <span>(\${appeal.user.email})</span></div>
                <p style="margin: 10px 0; color: var(--text-light-secondary); border-left: 2px solid var(--info-accent); padding-left: 10px;"><em>"\${appeal.content}"</em></p>
                <div style="display: flex; gap: 10px; margin-top: 10px;">
                    <form action="/api/admin/appeals/approve" method="POST" class="admin-form">
                        <input type="hidden" name="appealId" value="\${appeal.id}">
                        <button type="submit" class="btn-small btn-success">Aprovar (Desbanir)</button>
                    </form>
                    <form action="/api/admin/appeals/reject" method="POST" class="admin-form">
                        <input type="hidden" name="appealId" value="\${appeal.id}">
                        <button type="submit" class="btn-small btn-danger">Rejeitar</button>
                    </form>
                </div>
            \`;
            if (list.querySelector('.user-list-item').textContent.includes('Nenhum apelo')) {
                list.innerHTML = '';
            }
            list.prepend(newItem);
        });

        // --- Real-time para Desbanimento Direto ---
        document.getElementById('banned-users-list').addEventListener('submit', async (e) => {
            if (e.target.action.includes('/api/admin/unban')) {
                e.preventDefault();
                const form = e.target;
                const email = form.email.value;
                const response = await fetch(form.action, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email })
                });

                if (response.ok) {
                    const { unbannedUser } = await response.json();
                    // Remove o usuário da lista de banidos e adiciona na de ativos
                    moveUserToActiveList(unbannedUser);
                }
            }
        });

        // --- Real-time para Desbanimento (via aprovação de apelo) ---
        document.body.addEventListener('submit', async (e) => {
            if (e.target.action.includes('/api/admin/appeals/approve')) {
                e.preventDefault();
                const form = e.target;
                const appealId = form.appealId.value;
                const response = await fetch(form.action, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ appealId })
                });
                if (response.ok) {
                    const { unbannedUser } = await response.json();
                    // Remove o apelo da lista
                    document.getElementById('appeal-' + appealId)?.remove();
                    moveUserToActiveList(unbannedUser);
                } else {
                    alert('Falha ao aprovar apelo.');
                }
            }
        });

        function moveUserToActiveList(user) {
            // Remove o usuário da lista de banidos (se existir)
            const bannedList = document.getElementById('banned-users-list');
            const bannedUserItem = Array.from(bannedList.querySelectorAll('.user-list-item')).find(item => item.querySelector('input[name="email"]')?.value === user.email);
            bannedUserItem?.remove();

            // Adiciona o usuário à lista de ativos
            const activeList = document.getElementById('active-users-list');
            const template = document.getElementById('user-item-template');
            const clone = template.content.cloneNode(true);
            clone.querySelector('.user-info').innerHTML = \`\${user.username} <span>(\${user.email})</span>\`;
            // TODO: Adicionar forms de ban e give coins aqui se necessário no futuro
            activeList.prepend(clone);
        }
    `;

    res.send(renderDashboardPage(req.session, 'Admin Panel', content, adminScript));
});

app.post('/api/admin/tickets/close', isAuthenticated, isAdmin, async (req, res) => {
    const { ticketId } = req.body;
    const ticket = await prisma.ticket.update({
        where: { id: parseInt(ticketId, 10) },
        data: { status: 'closed' },
        include: { author: true },
    });

    if (ticket) {
        await logAdminAction(req.session.user.username, 'CLOSE_TICKET', `Fechou o ticket #${ticketId} de ${ticket.author.username}.`);
    }
    res.redirect('/admin');
});

// --- API para Doar/Adicionar Moedas (Admin) ---
app.post('/api/admin/give-coins', isAuthenticated, isAdmin, async (req, res) => {
    const { email, amount } = req.body;
    const amountNumber = parseInt(amount, 10);

    if (!email || !amountNumber || amountNumber <= 0) {
        return res.status(400).send('Email e uma quantidade válida de moedas são necessários.');
    }

    const targetUser = await prisma.user.findUnique({ where: { email } });

    if (targetUser) {
        const updatedUser = await prisma.user.update({ where: { email }, data: { coins: { increment: amountNumber } } });
        const logDetails = email === req.session.user.email ? `Adicionou ${amountNumber} moedas para si mesmo.` : `Doou ${amountNumber} moedas para ${updatedUser.username}.`;
        await logAdminAction(req.session.user.username, 'GIVE_COINS', logDetails);
        res.redirect('/admin');
    } else {
        res.status(404).send('Usuário não encontrado.');
    }
});


// --- Rota para Banir Usuário ---
app.post('/api/admin/ban', isAuthenticated, isAdmin, async (req, res) => {
    const { email, reason } = req.body;
    const userToBan = await prisma.user.update({
        where: { email },
        data: { isBanned: true, banReason: reason },
    });

    if (userToBan) {
        await logAdminAction(req.session.user.username, 'BAN_USER', `Baniu o usuário ${userToBan.username} (${email}). Motivo: ${reason}`);

        // Emite um evento de banimento para o usuário específico
        io.to(email).emit('banned', { reason: reason });

        // Envia e-mail de notificação de banimento
        const appealLink = `${process.env.BASE_URL || `http://localhost:${port}`}/appeal?userId=${userToBan.id}`;
        const emailHtml = createStyledEmail({
            title: 'Sua Conta Foi Banida',
            bodyContent: `
                <p style="color: #b3b3b3; font-size: 16px; line-height: 24px;">Olá, ${userToBan.username}.</p>
                <p style="color: #b3b3b3; font-size: 16px; line-height: 24px;">Sua conta no uberzer foi banida. Abaixo estão os detalhes:</p>
                <div style="background-color: #2a2a2a; padding: 15px; border-radius: 8px; margin: 20px 0; color: #e0e0e0;"><strong>Motivo:</strong> ${reason}</div>
                <p style="color: #b3b3b3; font-size: 16px; line-height: 24px;">Se você acredita que isso foi um erro, você pode fazer um apelo clicando no botão abaixo.</p>
            `,
            button: { text: 'Apelar do Banimento', link: appealLink }
        });

        sgMail.send({ to: email, from: { name: 'Suporte uberzer', email: process.env.EMAIL_USER }, subject: 'Notificação de Banimento - uberzer', html: emailHtml })
            .catch(err => console.error("Erro ao enviar e-mail de notificação de banimento:", err));
    }
    res.redirect('/admin');
});

app.post('/api/admin/unban', isAuthenticated, isAdmin, async (req, res) => {
    const { email } = req.body;
    const unbannedUser = await prisma.user.update({
        where: { email },
        data: { isBanned: false, banReason: null },
    });
    if (unbannedUser) {
        await logAdminAction(req.session.user.username, 'UNBAN_USER', `Desbaniu o usuário ${unbannedUser.username} (${email}).`);

        // Envia e-mail de notificação de desbanimento
        const emailHtml = createStyledEmail({
            title: 'Sua Conta Foi Reativada',
            bodyContent: `
                <p style="color: #b3b3b3; font-size: 16px; line-height: 24px;">Olá, ${unbannedUser.username}.</p>
                <p style="color: #b3b3b3; font-size: 16px; line-height: 24px;">Boas notícias! Sua conta no uberzer foi reativada por um administrador. Você já pode fazer login novamente.</p>
            `,
            button: { text: 'Acessar o Site', link: process.env.BASE_URL || `http://localhost:${port}` }
        });

        sgMail.send({ to: email, from: { name: 'Suporte uberzer', email: process.env.EMAIL_USER }, subject: 'Sua conta foi reativada - uberzer', html: emailHtml })
            .catch(err => console.error("Erro ao enviar e-mail de notificação de desbanimento:", err));
    }
    res.json({ success: true, unbannedUser });
});

// --- Rotas do Sistema de Links de Presente ---

app.post('/api/admin/generate-gift-link', isAuthenticated, isAdmin, async (req, res) => {
    const { giftType, coinsValue, characterValue } = req.body;

    let giftValue;
    let giftMeta = null;

    if (giftType === 'COINS') {
        giftValue = parseInt(coinsValue, 10).toString();
        if (isNaN(giftValue) || giftValue <= 0) {
            return res.status(400).send('Quantidade de moedas inválida.');
        }
    } else if (giftType === 'CHARACTER') {
        giftValue = characterValue;
        const charInfo = Object.values(charactersByRarity).flat().find(c => c.name === giftValue);
        if (!charInfo) {
            return res.status(400).send('Personagem inválido.');
        }
        giftMeta = charInfo.rarity.name; // Salva a raridade para exibir na tela de resgate
    } else {
        return res.status(400).send('Tipo de presente inválido.');
    }

    const token = crypto.randomBytes(16).toString('hex');
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutos de validade

    await prisma.giftLink.create({
        data: { token, giftType, giftValue, giftMeta, expiresAt }
    });

    await logAdminAction(req.session.user.username, 'CREATE_GIFT_LINK', `Gerou um link de presente: ${giftType} - ${giftValue}`);

    res.redirect('/admin');
});

app.get('/claim-gift', isAuthenticated, async (req, res) => {
    const { token } = req.query;
    if (!token) return res.status(400).send('Token não fornecido.');

    const giftLink = await prisma.giftLink.findUnique({ where: { token } });

    if (!giftLink || giftLink.claimed || giftLink.expiresAt < new Date()) {
        return res.send(renderAuthPage('Presente Inválido', '<div class="auth-container"><h1>Presente Inválido</h1><p>Este link de presente é inválido, já foi resgatado ou expirou.</p></div>'));
    }

    let giftDescription = '';
    if (giftLink.giftType === 'COINS') {
        giftDescription = `<strong>${giftLink.giftValue} Moedas</strong>`;
    } else {
        giftDescription = `o personagem <strong style="color: var(--info-accent);">${giftLink.giftValue}</strong> (${giftLink.giftMeta})`;
    }

    const content = `
        <div class="auth-container">
            <h1>Você Recebeu um Presente!</h1>
            <p>Você está prestes a resgatar ${giftDescription}.</p>
            <form action="/api/claim-gift" method="POST">
                <input type="hidden" name="token" value="${token}">
                <button type="submit" class="btn">Resgatar Presente</button>
            </form>
        </div>
    `;
    res.send(renderAuthPage('Resgatar Presente', content));
});

app.post('/api/claim-gift', isAuthenticated, async (req, res) => {
    const { token } = req.body;
    const userId = req.session.user.id;

    const giftLink = await prisma.giftLink.findFirst({
        where: { token, claimed: false, expiresAt: { gte: new Date() } }
    });

    if (!giftLink) {
        return res.send('<h1>Erro</h1><p>Este presente não pôde ser resgatado.</p>');
    }

    if (giftLink.giftType === 'COINS') {
        await prisma.user.update({ where: { id: userId }, data: { coins: { increment: parseInt(giftLink.giftValue) } } });
    } else if (giftLink.giftType === 'CHARACTER') {
        const charInfo = Object.values(charactersByRarity).flat().find(c => c.name === giftLink.giftValue);
        await prisma.character.create({ data: { name: charInfo.name, ability: charInfo.ability, rarityName: charInfo.rarity.name, rarityColor: charInfo.rarity.color, buffDescription: charInfo.buff.description, ownerId: userId } });
    }

    await prisma.giftLink.update({ where: { id: giftLink.id }, data: { claimed: true, claimedByUserId: userId } });

    res.send('<h1>Presente Resgatado!</h1><p>O presente foi adicionado à sua conta. Você pode fechar esta página.</p>');
});

// --- Rotas do Sistema de Apelação ---

app.get('/appeal', async (req, res) => {
    const { userId } = req.query;
    if (!userId) return res.status(400).send('Link de apelo inválido.');

    const user = await prisma.user.findUnique({ where: { id: userId } });

    if (!user || !user.isBanned) {
        return res.status(404).send('Usuário não encontrado ou não está banido.');
    }

    const existingAppeal = await prisma.banAppeal.findUnique({ where: { userId } });

    let content;
    if (existingAppeal) {
        content = `
            <div class="auth-container">
                <h1>Apelo já Enviado</h1>
                <p style="color: #aaa; margin-bottom: 20px;">Olá, <strong>${user.username}</strong>. Já recebemos seu apelo e ele está sendo analisado por nossa equipe.</p>
                <p>Status atual: <strong>${existingAppeal.status}</strong></p>
            </div>
        `;
    } else {
        content = `
            <div class="auth-container">
                <h1>Apelação de Banimento</h1>
                <p style="color: #aaa; margin-bottom: 20px;">Olá, <strong>${user.username}</strong>. Para solicitar a reativação da sua conta, escreva seu apelo e confirme que você leu e concorda em seguir as regras.</p>
                <form id="appeal-form" action="/api/appeal" method="POST">
                    <input type="hidden" name="userId" value="${userId}">
                    <div class="form-group">
                        <textarea name="content" rows="8" required placeholder="Escreva seu apelo aqui..." style="width: 100%; padding: 10px; border-radius: 8px; border: 1px solid #444; background-color: var(--bg-dark-tertiary); color: var(--text-light-primary); font-family: 'Poppins', sans-serif;"></textarea>
                    </div>
                    <div class="form-group" style="text-align: left; display: flex; align-items: center; gap: 10px;">
                        <input type="checkbox" id="terms" name="terms" required>
                        <label for="terms" style="margin: 0;">Eu li as regras e concordo em não repetir a infração.</label>
                    </div>
                    <button type="submit" class="btn">Solicitar Reativação</button>
                </form>
            </div>
        `;
    }

    res.send(renderAuthPage('Apelação de Banimento', content));
});

app.post('/api/appeal', async (req, res) => {
    const { userId, content } = req.body;
    const newAppeal = await prisma.banAppeal.create({
        data: {
            content,
            userId
        },
        include: { user: true }
    });

    // Notifica os admins em tempo real
    io.to('admin-room').emit('new appeal', newAppeal);

    res.send('<h1>Apelo Enviado</h1><p>Seu apelo foi enviado com sucesso e será analisado pela nossa equipe.</p>');
});

app.post('/api/admin/appeals/approve', isAuthenticated, isAdmin, async (req, res) => {
    const { appealId } = req.body;
    const appeal = await prisma.banAppeal.update({
        where: { id: parseInt(appealId) },
        data: { status: 'approved' },
        include: { user: true }
    });

    if (appeal) {
        await prisma.user.update({ where: { id: appeal.userId }, data: { isBanned: false, banReason: null } });
        await logAdminAction(req.session.user.username, 'APPROVE_APPEAL', `Aprovou o apelo e desbaniu o usuário ${appeal.user.username}.`);

        // Envia e-mail de notificação de apelo aprovado
        const emailHtml = createStyledEmail({
            title: 'Seu Apelo Foi Aprovado',
            bodyContent: `
                <p style="color: #b3b3b3; font-size: 16px; line-height: 24px;">Olá, ${appeal.user.username}.</p>
                <p style="color: #b3b3b3; font-size: 16px; line-height: 24px;">Boas notícias! Após análise, seu apelo de banimento foi aprovado e sua conta foi reativada. Seja bem-vindo de volta!</p>
            `,
            button: { text: 'Acessar o Site', link: process.env.BASE_URL || `http://localhost:${port}` }
        });

        sgMail.send({ to: appeal.user.email, from: { name: 'Suporte uberzer', email: process.env.EMAIL_USER }, subject: 'Apelo Aprovado - uberzer', html: emailHtml })
            .catch(err => console.error("Erro ao enviar e-mail de apelo aprovado:", err));
    }
    res.json({ success: true, unbannedUser: appeal.user });
});

app.post('/api/admin/appeals/reject', isAuthenticated, isAdmin, async (req, res) => {
    const { appealId } = req.body;
    const appeal = await prisma.banAppeal.update({
        where: { id: parseInt(appealId) },
        data: { status: 'rejected' },
        include: { user: true }
    });
    if (appeal) {
        await logAdminAction(req.session.user.username, 'REJECT_APPEAL', `Rejeitou o apelo do usuário ${appeal.user.username}.`);
    }
    res.redirect('/admin');
});

// --- Rota de Status (Página Inicial) ---
app.get('/', (req, res) => {
    // Redireciona para o dashboard se estiver logado, caso contrário, para a página de login.
    if (req.session.user) {
        res.redirect('/dashboard');
    } else {
        res.redirect('/register'); // Mudei para redirecionar para o cadastro como página inicial
    }
});

// --- Armazena sockets por email para fácil acesso ---
const onlineUsers = new Map();

// --- Lógica do Socket.IO para o Chat ---
io.on('connection', (socket) => {
    const user = socket.request.session.user;

    // Se por algum motivo não houver usuário na sessão, desconecta.
    if (!user) { return socket.disconnect(true); }

    // Associa o email do usuário ao seu socket e o coloca em uma "sala" com seu email (para notificações diretas)
    onlineUsers.set(user.email, socket.id);
    socket.join(user.email);

    console.log(`[CHAT] ${user.username} conectou.`);
    // Avisa a todos (menos o que acabou de entrar) que um novo usuário se conectou.
    socket.broadcast.emit('chat message', { username: 'Sistema', msg: `${user.username} entrou no chat.` });

    socket.on('disconnect', () => {
        onlineUsers.delete(user.email);
        console.log(`[CHAT] ${user.username} desconectou.`);
        // Avisa a todos que o usuário saiu.
        io.emit('chat message', { username: 'Sistema', msg: `${user.username} saiu do chat.` });
    });

    socket.on('chat message', async (msg) => {
        // Verifica se o usuário não foi banido no meio tempo
        const dbUser = await prisma.user.findUnique({ where: { id: user.id } });
        if (dbUser?.isBanned) {
            socket.emit('banned', { reason: dbUser.banReason });
            socket.disconnect(true);
            return;
        }
        // Quando recebe uma mensagem, envia para todos os clientes conectados.
        io.emit('chat message', { username: user.username, msg: msg });
    });

    // --- Lógica do Socket.IO para o Chat de Tickets ---

    // Admin entra na sala de notificações globais de admin
    socket.on('join admin room', () => {
        if (user.isAdmin) socket.join('admin-room');
    });

    // Jogador entra na "sala" de um ticket específico
    socket.on('join ticket room', async (ticketId) => {
        const ticket = await prisma.ticket.findUnique({ where: { id: ticketId } });
        // Validação: só pode entrar na sala se for o autor ou admin
        if (ticket && (ticket.authorId === user.id || user.isAdmin)) {
            socket.join(`ticket-${ticketId}`);
            console.log(`[TICKET] ${user.username} entrou na sala do ticket #${ticketId}`);
        }
    });

    // Recebe uma nova mensagem para um ticket
    socket.on('ticket message', async ({ ticketId, content }) => {
        const ticket = await prisma.ticket.findUnique({ where: { id: ticketId } });
        // Validação: só pode enviar mensagem se for o autor ou admin
        if (ticket && (ticket.authorId === user.id || user.isAdmin)) {
            // Se um admin responde, o ticket é reaberto
            if (user.isAdmin && ticket.status === 'closed') {
                await prisma.ticket.update({ where: { id: ticketId }, data: { status: 'open' } });
            }

            const newMessage = await prisma.ticketMessage.create({
                data: {
                    content,
                    ticketId: ticketId,
                    authorName: user.username,
                    isAdmin: user.isAdmin
                }
            });

            // Envia a nova mensagem para todos na sala do ticket
            io.to(`ticket-${ticketId}`).emit('new ticket message', newMessage);
        }
    });

    // --- Lógica do Socket.IO para a Arena de Batalha ---
    let battleState = null;

    socket.on('start battle', async () => {
        const dbUser = await prisma.user.findUnique({ where: { id: user.id }, include: { characters: true } });
        if (!dbUser) return;

        const { totalPower, totalHealth } = calculatePlayerBuffs(dbUser.characters);
        const opponentData = opponents[Math.floor(Math.random() * opponents.length)];

        battleState = {
            player: { id: dbUser.id, name: dbUser.username, health: totalHealth, maxHealth: totalHealth, power: totalPower, isDefending: false },
            opponent: { ...opponentData, maxHealth: opponentData.health },
            log: [],
            turn: 'player'
        };

        io.to(socket.id).emit('battle update', {
            log: `Uma batalha começou! Você enfrenta ${battleState.opponent.name}.`,
            player: battleState.player,
            opponent: battleState.opponent,
            isPlayerTurn: true
        });
    });

    socket.on('battle action', async (action) => {
        if (!battleState || battleState.turn !== 'player') return;

        let playerDamage = 0;
        let logMessage = '';

        // Turno do Jogador
        switch (action) {
            case 'fast_attack':
                playerDamage = Math.floor(battleState.player.power * 0.5 * (0.9 + Math.random() * 0.2)); // 50% do poder, 90-110% de variação
                logMessage = `Você usa um Ataque Rápido e causa ${playerDamage} de dano!`;
                break;
            case 'strong_attack':
                if (Math.random() > 0.3) { // 70% de chance de acertar
                    playerDamage = Math.floor(battleState.player.power * 1.0 * (0.8 + Math.random() * 0.4)); // 100% do poder, 80-120% de variação
                    logMessage = `Você usa um Ataque Forte e causa ${playerDamage} de dano!`;
                } else {
                    logMessage = 'Você usa um Ataque Forte, mas erra!';
                }
                break;
            case 'defend':
                battleState.player.isDefending = true;
                logMessage = 'Você se prepara para defender o próximo ataque.';
                break;
        }
        battleState.opponent.health = Math.max(0, battleState.opponent.health - playerDamage);
        io.to(socket.id).emit('battle update', { log: logMessage, player: battleState.player, opponent: battleState.opponent, isPlayerTurn: false });

        if (battleState.opponent.health <= 0) {
            await prisma.user.update({ where: { id: user.id }, data: { coins: { increment: 50 } } });
            return io.to(socket.id).emit('battle end', { win: true, message: 'VITÓRIA! Você ganhou 50 moedas!' });
        }

        // Turno do Oponente (após um delay)
        setTimeout(async () => {
            let opponentDamage = Math.floor(battleState.opponent.power * 0.6 * (0.8 + Math.random() * 0.4));
            let opponentLog = `${battleState.opponent.name} ataca!`;

            if (battleState.player.isDefending) {
                opponentDamage = Math.floor(opponentDamage * 0.3); // Defesa reduz 70% do dano
                opponentLog += ` Você defende e reduz o dano para ${opponentDamage}!`;
                battleState.player.isDefending = false;
            } else {
                opponentLog += ` Ele causa ${opponentDamage} de dano!`;
            }

            battleState.player.health = Math.max(0, battleState.player.health - opponentDamage);
            io.to(socket.id).emit('battle update', { log: opponentLog, logColor: 'var(--danger-accent)', player: battleState.player, opponent: battleState.opponent, isPlayerTurn: true });

            if (battleState.player.health <= 0) {
                const coinLoss = 25;
                const dbUser = await prisma.user.findUnique({ where: { id: user.id }, select: { coins: true } });
                const newCoins = Math.max(0, dbUser.coins - coinLoss);
                await prisma.user.update({ where: { id: user.id }, data: { coins: newCoins } });
                return io.to(socket.id).emit('battle end', { win: false, message: `DERROTA! Você perdeu 25 moedas.` });
            }

            battleState.turn = 'player';
        }, 1500);

        battleState.turn = 'opponent';
    });
});

// --- Inicia o servidor ---
server.listen(port, async () => { // Mudamos de app.listen para server.listen
    // Cria a conta de admin na inicialização, se não existir
    const adminUser = process.env.ADMIN_USERNAME;
    const adminEmail = `${adminUser}@admin.local`;

    if (adminUser && process.env.ADMIN_PASSWORD) {
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(process.env.ADMIN_PASSWORD, salt);
        await prisma.user.upsert({
            where: { email: adminEmail },
            update: { passwordHash, isAdmin: true },
            create: { email: adminEmail, username: adminUser, passwordHash, isAdmin: true, coins: 999999 },
        });
        console.log(`[SISTEMA] Conta de administrador '${adminUser}' criada/carregada.`);
    }

    console.log(`Servidor rodando na porta ${port}`);
    console.log(`Acesse http://localhost:${port}`);
});
