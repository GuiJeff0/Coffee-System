const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const nodemailer = require('nodemailer');
require('dotenv').config();

const connection = require('../connection'); // Certifique-se de que o caminho está correto
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

// Função para verificar se o usuário já existe
const userExists = async (email) => {
    return new Promise((resolve, reject) => {
        const query = "SELECT email FROM user WHERE email=?";
        connection.query(query, [email], (err, results) => {
            if (err) return reject(err);
            resolve(results.length > 0);
        });
    });
};

// Função para criar um novo usuário
const createUser = async (name, contactNumber, email, password) => {
    return new Promise((resolve, reject) => {
        const query = "INSERT INTO user (name, contactNumber, email, password, status, role) VALUES (?, ?, ?, ?, 'false', 'user')";
        connection.query(query, [name, contactNumber, email, password], (err, results) => {
            if (err) return reject(err);
            resolve(results);
        });
    });
};

// Função para encontrar um usuário por email
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
        // Verificar se o usuário já existe
        if (await userExists(email)) {
            return res.status(400).json({ message: "Email já existe" });
        }

        // Hash da senha
        const hashedPassword = await bcrypt.hash(password, 10);

        // Inserir o novo usuário no banco de dados
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
        // Verificar se o usuário existe
        const user = await findUserByEmail(email);
        if (user.length === 0) {
            return res.status(401).json({ message: "E-mail ou senha incorretos" });
        }

        // Comparar a senha fornecida com a armazenada no banco de dados
        const validPassword = await bcrypt.compare(password, user[0].password);
        if (!validPassword) {
            return res.status(401).json({ message: "E-mail ou senha incorretos" });
        }

        // Gerar um token JWT
        const token = jwt.sign({ userId: user[0].id }, process.env.JWT_SECRET, { expiresIn: '1h' });

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

        const resetToken = jwt.sign({ userId: user[0].id }, process.env.JWT_SECRET, { expiresIn: '1h' });

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

module.exports = router;

