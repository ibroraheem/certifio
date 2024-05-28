require('dotenv').config()
const express = require('express')
const cors = require("cors");
const morgan = require("morgan");
const passport = require('passport')
const connectDB = require('./config/db')
const swaggerUi = require('swagger-ui-express');
const swaggerDocument = require('./swagger.json');

const app = express()

require('./config/passport')(passport)
app.use(passport.initialize())
app.use(express.json())
app.use(morgan("dev"));
app.use(
    cors({
        origin: "*",
        methods: ["GET", "POST", "DELETE", "UPDATE", "PUT", "PATCH"],
        allowedHeaders: [
            "Content-Type",
            "Authorization",
            "Origin",
            "x-access-token",
            "X-Requested-With",
            "Accept",
            "Access-Control-Allow-Headers",
            "Access-Control-Request-Headers",
            "Access-Control-Allow-Origin",
            "Access-Control-Allow-Methods",
            "Access-Control-Allow-Credentials",
        ],
        credentials: true,
        optionsSuccessStatus: 200,
    })
);
app.get('/', async (req, res) => {
    res.status(200).send('Welcome to Certifio!')
})
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));
app.use('/auth', require('./routes/authRoute'))

connectDB()

const PORT = process.env.PORT || 5000

app.listen(PORT, () => console.log(`Server running on port ${PORT}`))