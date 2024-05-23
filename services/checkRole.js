require('dotenv').config();

function checkRole(req, res, next) {
    const { role } = res.locals;

    if (!role) {
        return res.status(403).json({ message: 'Role not found' });
    }

    if (role === process.env.USER) {
        return res.status(401).json({ message: 'Unauthorized: Insufficient role' });
    }

    next();
}

module.exports = { checkRole };
