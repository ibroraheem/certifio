// middleware/errorHandler.js
const errorHandler = (err, req, res, next) => {
    console.error(err);

    const statusCode = res.statusCode !== 200 ? res.statusCode : 500;

    res.status(statusCode).json({
        data: null,
        message: err.message || 'Server Error',
        errors: err.errors || [],
    });
};

module.exports = errorHandler;
