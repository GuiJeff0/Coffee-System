const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const nodemailer = require('nodemailer');

if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const auth = require('../services/authentication');
const checkRole = require('../services/checkRole');

const connection = require('../connection');
const router = express.Router();

// Middleware para validar dados de entrada
const validateSignup = [
    body('email').isEmail().withMessage('Formato de e-mail inválido'),
    body('password').isLength({ min: 6 }).withMessage('A senha deve ter pelo menos 6 caracteres'),
    body('name').notEmpty().withMessage('Nome é obrigatório'),
    body('contactNumber').notEmpty().withMessage('Número de contato é obrigatório'),
];

const validateLogin = [
    body('email').isEmail().withMessage('Formato de e-mail inválido'),
    body('password').notEmpty().withMessage('Senha é obrigatória'),
];

// Configuração do nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL,
        pass: process.env.PASSWORD
    }
});

// Funções auxiliares para interações com o banco de dados
const userExists = async (email) => {
    return new Promise((resolve, reject) => {
        const query = "SELECT email FROM user WHERE email=?";
        connection.query(query, [email], (err, results) => {
            if (err) return reject(err);
            resolve(results.length > 0);
        });
    });
};

const createUser = async (name, contactNumber, email, password) => {
    return new Promise((resolve, reject) => {
        const query = "INSERT INTO user (name, contactNumber, email, password, status, role) VALUES (?, ?, ?, ?, 'false', 'user')";
        connection.query(query, [name, contactNumber, email, password], (err, results) => {
            if (err) return reject(err);
            resolve(results);
        });
    });
};

const findUserByEmail = async (email) => {
    return new Promise((resolve, reject) => {
        const query = "SELECT id, email, password, role, status FROM user WHERE email=?";
        connection.query(query, [email], (err, results) => {
            if (err) return reject(err);
            resolve(results);
        });
    });
};

// Rota de registro de usuário
router.post('/signup', validateSignup, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { name, contactNumber, email, password } = req.body;

    try {
        if (await userExists(email)) {
            return res.status(400).json({ message: "Email já existe" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await createUser(name, contactNumber, email, hashedPassword);

        res.status(200).json({ message: "Registrado com sucesso" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Rota de login de usuário
router.post('/login', validateLogin, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
        const user = await findUserByEmail(email);
        if (user.length === 0) {
            return res.status(401).json({ message: "E-mail ou senha incorretos" });
        }

        const validPassword = await bcrypt.compare(password, user[0].password);
        if (!validPassword) {
            return res.status(401).json({ message: "E-mail ou senha incorretos" });
        }

        const token = jwt.sign({ userId: user[0].id }, process.env.ACCESS_TOKEN, { expiresIn: '1h' });
        res.status(200).json({ message: "Login bem-sucedido", token });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Rota de recuperação de senha
router.post('/forgotpassword', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await findUserByEmail(email);
        if (user.length === 0) {
            return res.status(404).json({ message: "Usuário não encontrado" });
        }

        const resetToken = jwt.sign({ userId: user[0].id }, process.env.ACCESS_TOKEN, { expiresIn: '1h' });

        const mailOptions = {
            from: process.env.EMAIL,
            to: email,
            subject: 'Recuperação de Senha',
            text: `Clique no link para resetar sua senha: ${process.env.FRONTEND_URL}/resetpassword?token=${resetToken}`
        };

        transporter.sendMail(mailOptions, (err, info) => {
            if (err) {
                return res.status(500).json({ message: 'Erro ao enviar email', error: err });
            }
            res.status(200).json({ message: 'Email de recuperação enviado com sucesso' });
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Rota para obter todos os usuários
router.get('/get', auth.authenticateToken, (req, res) => {
    const query = "SELECT id, name, email, contactNumber, status FROM user WHERE role ='user'";
    connection.query(query, (err, results) => {
        if (!err) {
            return res.status(200).json(results);
        } else {
            return res.status(500).json(err);
        }
    });
});

// Rota para atualizar o status do usuário
router.patch('/update', auth.authenticateToken, (req, res) => {
    let user = req.body;
    const query = "UPDATE user SET status=? WHERE id=?";
    connection.query(query, [user.status, user.id], (err, results) => {
        if (!err) {
            if (results.affectedRows == 0) {
                return res.status(404).json({ message: "ID do usuário não encontrado" });
            }
            return res.status(200).json({ message: "Status do usuário atualizado com sucesso" });
        } else {
            return res.status(500).json(err);
        }
    });
});

// Rota para verificar o token
router.get('/checkToken', auth.authenticateToken, (req, res) => {
    return res.status(200).json({ message: "true" });
});

module.exports = router;


