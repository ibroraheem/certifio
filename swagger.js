const swaggerAutogen = require('swagger-autogen')();

const doc = {
    info: {
        title: 'CERTIFIO',
        description: 'Certifio API documentation',
    },
    host: 'certifio-1.onrender.com', // Change this to your host
    schemes: ['https'], 
};

const outputFile = './swagger-output.json';
const endpointsFiles = ['./routes/authRoute.js'];

swaggerAutogen(outputFile, endpointsFiles, doc);
