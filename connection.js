const mysql = require('mysql');
const winston = require('winston');

// Create a logger instance
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message }) => {
            return `${timestamp} [${level.toUpperCase()}]: ${message}`;
        })
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'app.log' })
    ]
});

// MySQL connection configuration
const connectionConfig = {
    port: process.env.DB_PORT,
    host: process.env.DB_HOST,
    user: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
};

// Create a connection instance
let connection = mysql.createConnection(connectionConfig);

// Function to handle connection with retry logic
function connectWithRetry(maxRetries = 5, delay = 1000) {
    let attempts = 0;

    function tryConnect() {
        connection.connect((err) => {
            if (!err) {
                logger.info("Connected to the database successfully");
            } else {
                attempts++;
                logger.error(`Connection attempt ${attempts} failed: ${err.message}`);

                if (attempts < maxRetries) {
                    setTimeout(() => {
                        logger.info(`Retrying connection (attempt ${attempts + 1})...`);
                        tryConnect();
                    }, delay);
                } else {
                    logger.error("Max retries reached. Could not connect to the database.");
                }
            }
        });
    }

    tryConnect();
}

// Call the function to attempt connection
connectWithRetry();

// Export the connection instance
module.exports = connection;
